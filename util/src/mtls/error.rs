use rsa::{pkcs1::Error as Pkcs1Error, Error as RsaError};
use std::{
    error::Error as StdError,
    fmt::{self, Display, Formatter},
    io::Error as IoError,
};

/// Error types
#[derive(Debug)]
pub enum Error {
    /// pkcs1-related errors
    Pkcs1(Pkcs1Error),
    /// RSA-related errors
    Rsa(RsaError),
    /// io-related errors
    Io(IoError),
    /// The client is not yet ready to receive data.
    NotReady,
    /// The connection has been lost due to an error during transmission.
    SocketDied,
    /// Request timed out
    Timeout,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Pkcs1(error) => error.fmt(f),
            Self::Rsa(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
            Self::NotReady => {
                f.write_str("Public key not received yet. Consider awaiting the `handshake`.")
            }
            Self::SocketDied => {
                f.write_str("Transmission interrupted due to an error. Consider reconnecting.")
            }
            Self::Timeout => f.write_str("Key exchange timed out. Please try reconnecting."),
        }
    }
}

impl StdError for Error {}

macro_rules! impl_from {
    ($( $ident:ident ),*) => {
        $(
            paste::paste! {
                impl From<[<$ident Error>]> for Error {
                    fn from(error: [<$ident Error>]) -> Self {
                        Self::$ident(error)
                    }
                }
            }
        )*
    };
}

impl_from!(Io, Rsa, Pkcs1);
