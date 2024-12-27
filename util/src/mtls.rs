use rand::thread_rng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    traits::PublicKeyParts,
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

#[derive(Debug)]
pub struct Mtls {
    read: OwnedReadHalf,
    write: OwnedWriteHalf,
    private_key: RsaPrivateKey,
    public_key: Option<RsaPublicKey>,
}

impl Mtls {
    pub fn new(stream: TcpStream, private_key: RsaPrivateKey) -> Self {
        let (read, write) = stream.into_split();
        Self {
            read,
            write,
            public_key: None,
            private_key,
        }
    }

    pub fn set_public_key(&mut self, public_key: RsaPublicKey) {
        self.public_key = Some(public_key)
    }

    pub async fn handshake(&mut self) -> Option<()> {
        let cert_length = self.read.read_u64().await.ok()?;

        let br = BufReader::new(&mut self.read);
        let mut cert = Vec::new();

        let mut handle = br.take(cert_length);
        handle.read_to_end(&mut cert).await.ok()?;
        self.public_key = Some(RsaPublicKey::from_pkcs1_der(&cert).unwrap());

        Some(())
    }

    pub async fn send_public_key(&mut self) -> Option<()> {
        let cert = RsaPublicKey::from(&self.private_key)
            .to_pkcs1_der()
            .unwrap();
        let cert = cert.as_bytes();
        self.write.write_u64(cert.len() as u64).await.ok()?;
        self.write.write_all(cert).await.ok()?;
        Some(())
    }

    pub async fn send(&mut self, data: &[u8]) -> Option<()> {
        send(&mut self.write, self.public_key.as_ref().unwrap(), data).await
    }

    pub async fn receive(&mut self) -> Option<Vec<u8>> {
        receive(&mut self.read, &self.private_key).await
    }
}

pub async fn send(
    stream: &mut OwnedWriteHalf,
    public_key: &RsaPublicKey,
    data: &[u8],
) -> Option<()> {
    let mut encrypted_buffer = Vec::new();
    let mut bw = BufWriter::new(&mut encrypted_buffer);

    let block_size = public_key.size() - 11;
    let block_count = data.len().div_ceil(block_size);

    for i in 0..block_count {
        let encrypted = public_key
            .encrypt(
                &mut thread_rng(),
                Pkcs1v15Encrypt,
                &data[(i * block_size)..(((i + 1) * block_size).min(data.len()))],
            )
            .ok()?;
        bw.write_all(&encrypted).await.ok()?;
    }

    stream.write_u64(block_count as u64).await.ok()?;
    bw.flush().await.ok()?;
    stream.write_all(&encrypted_buffer).await.ok()?;

    Some(())
}

pub async fn receive(stream: &mut OwnedReadHalf, private_key: &RsaPrivateKey) -> Option<Vec<u8>> {
    let block_count = stream.read_u64().await.ok()?;
    let block_size = private_key.size();
    let mut decrypted = Vec::new();

    for _ in 0..block_count {
        let mut handle = stream.take(block_size as u64);
        let mut encrypted = Vec::new();
        handle.read_to_end(&mut encrypted).await.ok()?;

        decrypted.append(&mut private_key.decrypt(Pkcs1v15Encrypt, &encrypted).unwrap());
    }

    Some(decrypted)
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
    tokio::join!(
        server_handler_mtls.handshake(),
        client_mtls.send_public_key()
    );

    let msg = b"a repetitive message".repeat(64);

    client_mtls.send(&msg).await.unwrap();
    server_handler_mtls.send(&msg).await.unwrap();

    let server_received = server_handler_mtls.receive().await.unwrap();
    let client_received = client_mtls.receive().await.unwrap();

    assert_eq!(msg, server_received);
    assert_eq!(msg, client_received);
}
