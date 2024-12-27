mod error;

pub use error::Error;
use rand::thread_rng;
use rsa::{traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The mTLS payload transmitted over TCP or UDP. Maximum 16MiB - 15B of data
/// could transmitted in single payload. A single payload can transmit up to
/// 16 MiB of data.
pub struct MtlsPayload {
    /// Reserved for future se.
    pub version: u16,
    /// Length of the payload
    pub length: u16,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

/// Calculates the maximum TCP payload length that can be carried by the
/// encrypted tunnel.
pub fn max_payload_size(block_size: u16) -> u16 {
    let block_count = u16::MAX / block_size;
    (block_size - 11) * block_count - 5
}

impl MtlsPayload {
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            version: 0,
            length: payload.len() as u16,
            payload,
        }
    }

    /// Retrieves and decrypts a mTLS payload.
    pub async fn collect_once<R: AsyncReadExt + Unpin>(
        br: &mut R,
        private_key: &RsaPrivateKey,
    ) -> Result<Self, Error> {
        let _version = br.read_u16().await?;
        let length = br.read_u16().await?;

        if length > max_payload_size(private_key.size() as u16) {
            return Err(Error::PayloadTooLong);
        }

        let block_size = private_key.size();
        let block_count = length.div_ceil((block_size - 11) as u16);

        let mut payload = Vec::with_capacity((block_size - 11) * block_count as usize);

        for _ in 0..block_count {
            let mut handle = br.take(block_size as u64);
            let mut encrypted = Vec::with_capacity(block_size);

            handle.read_to_end(&mut encrypted).await?;

            payload.append(&mut private_key.decrypt(Pkcs1v15Encrypt, &encrypted)?);
        }

        Ok(MtlsPayload::new(payload))
    }

    /// Writes the payload into the buffer.
    pub async fn write<W: AsyncWriteExt + Unpin>(
        self,
        bw: &mut W,
        public_key: &RsaPublicKey,
    ) -> Result<(), Error> {
        if self.length > max_payload_size(public_key.size() as u16) {
            return Err(Error::PayloadTooLong);
        }

        bw.write_u16(self.version).await?;
        bw.write_u16(self.length).await?;

        let block_size = public_key.size() - 11;
        let block_count = self.length.div_ceil(block_size as u16) as usize;

        for i in 0..block_count {
            let encrypted = public_key.encrypt(
                &mut thread_rng(),
                Pkcs1v15Encrypt,
                &self.payload[(i * block_size)..((i + 1) * block_size).min(self.length as usize)],
            )?;

            bw.write_all(&encrypted).await?;
        }

        Ok(())
    }
}
