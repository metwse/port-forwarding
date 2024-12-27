mod error;

#[cfg(test)]
mod tests;

mod payload;

use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use std::{sync::Mutex as StdMutex, time::Duration};
use tokio::{
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::Mutex,
};

pub use error::Error;
pub use payload::{max_payload_size, MtlsPayload};

/// Micro TLS Tunnel is a cryptographic protocol that ensures secure
/// communication over the Internet.
#[derive(Debug)]
pub struct Mtls {
    read: Mutex<OwnedReadHalf>,
    write: Mutex<OwnedWriteHalf>,
    private_key: RsaPrivateKey,
    public_key: Option<RsaPublicKey>,
    state: StdMutex<MtlsState>,
    timeout: Option<Duration>,
}

/// mTLS state
#[derive(Debug, Clone)]
pub enum MtlsState {
    /// The client has not yet received the public key.
    AwaitingPublicKey,
    /// The mTLS tunnel is established and the certificate has been acquired.
    Authenticated,
    /// An error occurred during transmission.
    TransmitError,
}

impl Mtls {
    /// Creates a new mTLS tunnel. The `public_key`, which should be acquired
    /// from the peer, is optional until messages are sent. It can be obtained
    /// using the `handshake` or `set_public_key` functions.
    pub fn new(stream: TcpStream, private_key: RsaPrivateKey) -> Self {
        let (read, write) = stream.into_split();
        Self {
            read: Mutex::new(read),
            write: Mutex::new(write),
            public_key: None,
            private_key,
            state: StdMutex::new(MtlsState::AwaitingPublicKey),
            timeout: None,
        }
    }

    /// The duration before the key exchange times out.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout
    }

    /// Sets the `public_key`, typically used for hard-coded keys. To ensure
    /// security, at least one of the two public keys must be hard-coded.
    pub fn set_public_key(&mut self, public_key: RsaPublicKey) {
        self.public_key = Some(public_key);
        self.set_state(MtlsState::Authenticated)
    }

    fn set_state(&self, state: MtlsState) {
        *self.state.lock().unwrap() = state
    }

    /// Returns the current state of the mTLS connection.
    pub fn get_state(&self) -> MtlsState {
        (*self.state.lock().unwrap()).clone()
    }

    /// Retrieves the `public_key` from the peer.  
    pub async fn handshake(&mut self) -> Result<(), Error> {
        match self.timeout {
            Some(duration) => {
                tokio::select! {
                    cert = self.receive() => {
                        self.handshake_inner(cert).await
                    },
                    _ = tokio::time::sleep(duration) => {
                        self.set_state(MtlsState::TransmitError);
                        Err(Error::Timeout)
                    }
                }
            }
            None => self.handshake_inner(self.receive().await).await,
        }
    }

    async fn handshake_inner(&mut self, cert: Result<Vec<u8>, Error>) -> Result<(), Error> {
        match cert {
            Ok(cert) => match RsaPublicKey::from_pkcs1_der(&cert) {
                Ok(cert) => {
                    self.set_public_key(cert);
                    Ok(())
                }
                Err(e) => {
                    self.set_state(MtlsState::TransmitError);
                    Err(Error::Pkcs1(e))
                }
            },
            Err(e) => {
                self.set_state(MtlsState::TransmitError);
                Err(e)
            }
        }
    }

    /// Sends the `public_key` to the peer for key exchange.
    pub async fn send_public_key(&mut self) -> Result<(), Error> {
        match RsaPublicKey::from(&self.private_key).to_pkcs1_der() {
            Ok(cert) => {
                let cert = cert.as_bytes();
                self.send(cert).await.unwrap();
                Ok(())
            }
            Err(e) => {
                self.set_state(MtlsState::TransmitError);
                Err(Error::Pkcs1(e))
            }
        }
    }

    /// Encrypts the data and transmits it to the peer.
    pub async fn send(&self, data: &[u8]) -> Result<(), Error> {
        match self.get_state() {
            MtlsState::Authenticated => {
                let sent: Result<(), Error> = async {
                    let stream = &mut *(self.write.lock().await);
                    MtlsPayload::new(data.to_owned())
                        .write(stream, self.public_key.as_ref().unwrap())
                        .await?;
                    Ok(())
                }.await;

                match sent {
                    Err(e) => {
                        self.set_state(MtlsState::TransmitError);
                        Err(e)
                    }
                    Ok(ok) => Ok(ok),
                }
            }
            MtlsState::AwaitingPublicKey => Err(Error::NotReady),
            MtlsState::TransmitError => Err(Error::SocketDied),
        }
    }

    /// Receives and decrypts data from the peer.
    pub async fn receive(&self) -> Result<Vec<u8>, Error> {
        match self.get_state() {
            MtlsState::TransmitError => Err(Error::SocketDied),
            _ => {
                let received = async {
                    let stream = &mut *(self.read.lock().await);
                    let payload = MtlsPayload::collect_once(stream, &self.private_key).await?;
                    Ok(payload.payload)
                }.await;

                match received {
                    Err(e) => {
                        self.set_state(MtlsState::TransmitError);
                        Err(e)
                    }
                    Ok(ok) => Ok(ok),
                }
            },
        }
    }
}
