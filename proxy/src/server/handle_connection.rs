use crate::connection::*;
use ptls::Ptls;
use rand::Rng;
use std::{sync::Arc, time::Duration};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use util::*;

impl super::Server {
    pub(crate) async fn handle_connection(self: Arc<Self>, tcp: TcpStream) -> Option<()> {
        let mut server_ptls = Ptls::new(tcp.into_split(), self.private_key.clone());
        server_ptls.handshake().await.ok()?;
        let server_ptls = Arc::new(server_ptls);

        let mut connection_state = ConnectionState::Socket;

        while let Ok(cmd) = server_ptls.receive().await {
            let cmd: Cmd = if let Ok(cmd) = bincode::deserialize(&cmd) {
                cmd
            } else {
                continue;
            };

            if let Some(result) = self
                .handle_command(cmd, &mut connection_state, &server_ptls)
                .await
            {
                server_ptls
                    .send(&bincode::serialize(&result).ok()?)
                    .await
                    .ok()?;
            }

            if let ConnectionState::PortForward { .. } = connection_state {
                break;
            }
        }

        if let ConnectionState::PortForward { kind, id, .. } = connection_state {
            match kind {
                ForwardKind::Share => {
                    let receiver;
                    loop {
                        if let Some(r) = self.forward_connections.lock().await.remove(&id) {
                            receiver = r;
                            break;
                        }

                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }

                    let (target_r, target_w) = receiver;
                    let (r, w) = Arc::into_inner(server_ptls).unwrap().into_inner();

                    copy_bidirectional((r, w), (target_r, target_w)).await;
                }
                ForwardKind::Receive => {
                    let mut forward_connections = self.forward_connections.lock().await;

                    // TODO: REMOVE UNWRAP
                    forward_connections
                        .insert(id, Arc::into_inner(server_ptls).unwrap().into_inner());
                }
            }
        }

        Some(())
    }

    async fn handle_command(
        &self,
        cmd: Cmd,
        connection_state: &mut ConnectionState,
        server_ptls: &Arc<Ptls<OwnedReadHalf, OwnedWriteHalf>>,
    ) -> Option<Cmd> {
        println!("handled: {cmd:?} {connection_state:?}");
        match &connection_state {
            ConnectionState::Socket => {
                if let Cmd::Authenticate { token } = cmd {
                    let token = String::from_utf8(token).ok()?;
                    let client = sqlx::query!(
                        "SELECT hostname, permission_level FROM clients WHERE key = ?",
                        token
                    )
                    .fetch_optional(&self.sqlite)
                    .await;

                    if let Ok(Some(client)) = client {
                        let mut connections = self.connections.lock().await;

                        *connection_state = ConnectionState::Authorized {
                            hostname: client.hostname.clone(),
                            permission_level: bincode::deserialize(&client.permission_level)
                                .ok()?,
                        };

                        if connections.get(&client.hostname).is_some() {
                            return None;
                        }
                        connections.insert(client.hostname, Arc::clone(server_ptls));
                    }
                }
                None
            }
            ConnectionState::Authorized {
                permission_level,
                hostname,
            } => match cmd {
                Cmd::SharePort { port, id } => {
                    *connection_state = ConnectionState::PortForward {
                        hostname: hostname.clone(),
                        kind: ForwardKind::Share,
                        port,
                        id,
                    };
                    None
                }
                Cmd::GetPort {
                    hostname: requested_hostname,
                    port,
                } => {
                    if !permission_level.at_least(&PermissionLevel::Standart) {
                        return None;
                    }
                    let id: u64 = rand::thread_rng().r#gen();
                    loop {
                        if let Some(connection) =
                            self.connections.lock().await.get(&requested_hostname)
                        {
                            connection
                                .send(&bincode::serialize(&Cmd::SharePort { port, id }).unwrap())
                                .await
                                .ok();

                            *connection_state = ConnectionState::PortForward {
                                hostname: hostname.clone(),
                                kind: ForwardKind::Receive,
                                port,
                                id,
                            };

                            break;
                        };

                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    None
                }
                Cmd::AddClient {
                    username, token, ..
                } => {
                    if !permission_level.at_least(&PermissionLevel::Admin(0)) {
                        return None;
                    }

                    let blob = bincode::serialize(&util::PermissionLevel::Standart).unwrap();
                    if sqlx::query_scalar!(
                        "INSERT INTO clients SELECT ?, ?, ?;",
                        username,
                        blob,
                        token
                    )
                    .fetch_optional(&self.sqlite)
                    .await
                    .is_ok()
                    {
                        println!("user added: {}", username)
                    };
                    None
                }
                _ => None,
            },
            ConnectionState::PortForward { .. } => None,
        }
    }
}
