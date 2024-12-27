use rsa::Error as RsaError;
use std::{error::Error as StdError, fmt::Display};
use tokio::io::Error as IoError;

#[derive(Debug)]
pub enum Error {
    UnsupportedVersion(u16),
    PayloadTooLong,
    Io(IoError),
    Rsa(RsaError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(f, "Unsupported version {version}"),
            Self::PayloadTooLong => {
                f.write_str("A single payload can transmit up to 16 MiB - 15 bytes of data.")
            }
            Self::Io(error) => error.fmt(f),
            Self::Rsa(error) => error.fmt(f),
        }
    }
}

impl StdError for Error {}

error_impl_from!(Io, Rsa);
