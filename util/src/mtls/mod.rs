mod error;

use rand::thread_rng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    traits::PublicKeyParts,
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use std::{sync::Mutex as StdMutex, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::Mutex,
};

pub use error::Error;

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
                match send(&self.write, self.public_key.as_ref().unwrap(), data).await {
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
            _ => match receive(&self.read, &self.private_key).await {
                Err(e) => {
                    self.set_state(MtlsState::TransmitError);
                    Err(e)
                }
                Ok(ok) => Ok(ok),
            },
        }
    }
}

async fn send(
    stream: &Mutex<OwnedWriteHalf>,
    public_key: &RsaPublicKey,
    data: &[u8],
) -> Result<(), Error> {
    let stream = &mut *(stream.lock().await);

    // PKCS1 v1.5 encryption padding is at most 11 bytes.
    let block_size = public_key.size() - 11;
    let block_count = data.len().div_ceil(block_size);

    let mut encrypted_buffer = Vec::with_capacity(block_count * block_size);
    let mut bw = BufWriter::new(&mut encrypted_buffer);

    for i in 0..block_count {
        let encrypted = public_key.encrypt(
            &mut thread_rng(),
            Pkcs1v15Encrypt,
            &data[(i * block_size)..(((i + 1) * block_size).min(data.len()))],
        )?;
        bw.write_all(&encrypted).await?;
    }

    stream.write_u64(block_count as u64).await?;
    bw.flush().await?;
    stream.write_all(&encrypted_buffer).await?;

    Ok(())
}

async fn receive(
    stream: &Mutex<OwnedReadHalf>,
    private_key: &RsaPrivateKey,
) -> Result<Vec<u8>, Error> {
    let stream = &mut *(stream.lock().await);

    let block_count = stream.read_u64().await?;
    let block_size = private_key.size();
    let mut decrypted = Vec::with_capacity(block_size * block_count as usize);

    for _ in 0..block_count {
        let mut handle = stream.take(block_size as u64);
        let mut encrypted = Vec::with_capacity(block_size);
        handle.read_to_end(&mut encrypted).await?;

        decrypted.append(&mut private_key.decrypt(Pkcs1v15Encrypt, &encrypted).unwrap());
    }

    decrypted.shrink_to_fit();

    Ok(decrypted)
}

#[tokio::test]
async fn mtls() {
    let mut rng = thread_rng();

    let server_private = RsaPrivateKey::new(&mut rng, 512).unwrap();
    let server_public = RsaPublicKey::from(&server_private);

    let client_private = RsaPrivateKey::new(&mut rng, 512).unwrap();

    let server = tokio::net::TcpListener::bind("localhost:7811")
        .await
        .unwrap();

    let (tcp_stream, accept) = tokio::join!(TcpStream::connect("localhost:7811"), server.accept());
    let client = tcp_stream.unwrap();
    let (peer, _) = accept.unwrap();

    let mut client_mtls = Mtls::new(client, client_private);
    client_mtls.set_public_key(server_public);

    let mut server_handler_mtls = Mtls::new(peer, server_private);
    let (server_handshake_result, client_send_result) = tokio::join!(
        server_handler_mtls.handshake(),
        client_mtls.send_public_key()
    );
    server_handshake_result.expect("Server could not retrieve certificate");
    client_send_result.expect("Client could not send certificate");

    let msg = b"a repetitive message".repeat(64);

    client_mtls.send(&msg).await.unwrap();
    server_handler_mtls.send(&msg).await.unwrap();

    let server_received = server_handler_mtls.receive().await.unwrap();
    let client_received = client_mtls.receive().await.unwrap();

    assert_eq!(msg, server_received);
    assert_eq!(msg, client_received);
}
