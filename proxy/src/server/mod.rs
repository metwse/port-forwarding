/// TCP port forwarding module.
pub mod tcp;

use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use tokio::net::{TcpListener, ToSocketAddrs};

/// Server builer struct.
#[derive(Default)]
pub struct ServerBuilder {
    private_key: Option<RsaPrivateKey>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn private_key(mut self, private_key: &str) -> Self {
        self.private_key = Some(
            DecodeRsaPrivateKey::from_pkcs1_pem(private_key).expect("Cannot decode pkcs1 pem"),
        );
        self
    }

    pub fn private_key_file(mut self, private_key_file: &str) -> Self {
        self.private_key = Some(
            DecodeRsaPrivateKey::read_pkcs1_pem_file(private_key_file).expect("Cannot decode pkcs1 pem"),
        );
        self
    }

    pub fn build(mut self) -> Server {
        Server {
            private_key: self.private_key.take().expect("Private key is not given"),
        }
    }
}

/// Port forwarding proxy server.
pub struct Server {
    private_key: RsaPrivateKey,
}

impl Server {
    /// Serves the proxy server.
    pub async fn serve<T: ToSocketAddrs>(self, addr: T) -> ! {
        let listener = TcpListener::bind(addr).await.unwrap();

        loop {
            let mut socket = match listener.accept().await {
                Ok((socket, _)) => socket,
                Err(_) => continue,
            };

            if socket.set_ttl(16).is_err() {
                continue;
            }

            let conneciton = self.tcp_handshake(&mut socket).await;
        }
    }
}
