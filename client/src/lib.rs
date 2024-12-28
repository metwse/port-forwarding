use ptls::Ptls;
use rand::thread_rng;
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPrivateKey, RsaPublicKey};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use util::*;

pub struct Client {}

impl Client {
    pub async fn connect(addr: &str, public_key: &str, token: &str) {
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
                            let client_private = RsaPrivateKey::new(&mut thread_rng(), 1024).unwrap();

                            let mut client_ptls = Ptls::new(forward_client.into_split(), client_private);
                            client_ptls.set_public_key(server_public.clone());
                            client_ptls.send_public_key().await.unwrap();

                            client_ptls
                                .send(
                                    &bincode::serialize(&Cmd::Authenticate {
                                        token: token.as_bytes().to_vec(),
                                    })
                                    .unwrap(),
                                )
                                .await.unwrap();

                            client_ptls
                                .send(
                                    &bincode::serialize(&Cmd::SharePort {
                                        port, id
                                    })
                                    .unwrap(),
                                )
                                .await.unwrap();

                            let (r, w) = client_ptls.into_inner();
                            let (target_r, target_w) = TcpStream::connect(&format!("localhost:{port}")).await.unwrap().into_split();

                            copy_bidirectional((r, w), (target_r, target_w)).await;
                        }
                        Cmd::Noop => {},
                        _ => {}
                    }
                }
            }
        });

        loop {
            client_ptls
                .send(&bincode::serialize(&Cmd::Noop).unwrap())
                .await
                .ok();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
