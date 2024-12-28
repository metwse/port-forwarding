use ptls::Ptls;
use rand::thread_rng;
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;
use tokio::{
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use util::*;

pub struct Client {}

impl Client {
    pub async fn connect(addr: &str, public_key: &str, token: &str) {
        macro_rules! print {
            ($text:expr) => {{
                let mut stdout = io::stdout();
                stdout.write_all($text.as_bytes()).await.ok();
                stdout.flush().await.ok();
            }};
        }

        let client = TcpStream::connect(addr)
            .await
            .expect(" connect to the remote add");

        let client_private = RsaPrivateKey::new(&mut thread_rng(), 1024).unwrap();
        let server_public =
            RsaPublicKey::read_pkcs1_pem_file(public_key).expect("Cannot read server public key");

        let mut client_ptls = Ptls::new(client.into_split(), client_private);
        client_ptls.set_public_key(server_public.clone());
        client_ptls
            .send_public_key()
            .await
            .expect("Cannot send public key to the server");

        let client_ptls = Arc::new(client_ptls);

        client_ptls
            .send(
                &bincode::serialize(&Cmd::Authenticate {
                    token: token.as_bytes().to_vec(),
                })
                .unwrap(),
            )
            .await
            .expect("Authentication failed");

        tokio::spawn({
            let client_ptls = Arc::clone(&client_ptls);
            let server_public = server_public.clone();
            let token = token.to_owned();
            let addr = addr.to_owned();

            async move {
                while let Ok(received) = client_ptls.receive().await {
                    let cmd: Cmd = if let Ok(cmd) = bincode::deserialize(&received) {
                        cmd
                    } else {
                        continue;
                    };

                    match cmd {
                        Cmd::SharePort { port, id } => {
                            let forward_client = TcpStream::connect(&addr).await.unwrap();
                            let client_private =
                                RsaPrivateKey::new(&mut thread_rng(), 1024).unwrap();

                            let mut client_ptls =
                                Ptls::new(forward_client.into_split(), client_private);
                            client_ptls.set_public_key(server_public.clone());
                            client_ptls.send_public_key().await.unwrap();

                            client_ptls
                                .send(
                                    &bincode::serialize(&Cmd::Authenticate {
                                        token: token.as_bytes().to_vec(),
                                    })
                                    .unwrap(),
                                )
                                .await
                                .unwrap();

                            client_ptls
                                .send(&bincode::serialize(&Cmd::SharePort { port, id }).unwrap())
                                .await
                                .unwrap();

                            let (r, w) = client_ptls.into_inner();
                            let (target_r, target_w) =
                                TcpStream::connect(&format!("localhost:{port}"))
                                    .await
                                    .unwrap()
                                    .into_split();

                            tokio::spawn(copy_bidirectional((r, w), (target_r, target_w)));
                        }
                        Cmd::Noop => {}
                        _ => {}
                    }
                }
            }
        });

        let stdin = io::stdin();

        let mut br = BufReader::new(stdin);

        loop {
            print!("proxy > ");
            let mut line = String::new();
            if br.read_line(&mut line).await.is_err() {
                continue;
            }

            line.pop();
            let line = line.split(" ").collect::<Vec<&str>>();

            match line[0] {
                "get" => {
                    let hostname = line[1].to_owned();
                    let port: Option<u32> = line[2].parse().ok();
                    let local_port: Option<u32> = line[3].parse().ok();

                    if let (Some(port), Some(local_port)) = (port, local_port) {
                        let server = TcpListener::bind(&format!("localhost:{local_port}"))
                            .await
                            .unwrap();

                        let addr = addr.to_owned();
                        let server_public = server_public.to_owned();
                        let token = token.to_owned();

                        tokio::spawn(async move {
                            let forward_client = TcpStream::connect(addr).await.unwrap();
                            let client_private =
                                RsaPrivateKey::new(&mut thread_rng(), 1024).unwrap();

                            let mut client_ptls =
                                Ptls::new(forward_client.into_split(), client_private);
                            client_ptls.set_public_key(server_public.clone());
                            client_ptls.send_public_key().await.unwrap();

                            client_ptls
                                .send(
                                    &bincode::serialize(&Cmd::Authenticate {
                                        token: token.as_bytes().to_vec(),
                                    })
                                    .unwrap(),
                                )
                                .await
                                .unwrap();

                            client_ptls
                                .send(
                                    &bincode::serialize(&Cmd::GetPort { hostname, port }).unwrap(),
                                )
                                .await
                                .unwrap();

                            let (r, w) = client_ptls.into_inner();
                            if let Ok((stream, _)) = server.accept().await {
                                let (target_r, target_w) = stream.into_split();
                                copy_bidirectional((r, w), (target_r, target_w)).await;
                            };
                        });
                        print!("requested port\n");
                    } else {
                        print!("cannot parse port\n");
                    }
                }
                "add_usr" => {
                    client_ptls
                        .send(
                            &bincode::serialize(&Cmd::AddClient {
                                username: line[1].to_owned(),
                                token: line[2].to_owned(),
                                permission_level: PermissionLevel::Standart,
                            })
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                }
                _ => {
                    print!("unknown command\n");
                }
            }
        }
    }
}
