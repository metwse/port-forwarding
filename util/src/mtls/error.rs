use super::payload::Error as PayloadError;
use rsa::pkcs1::Error as Pkcs1Error;
use std::{
    error::Error as StdError,
    fmt::{self, Display, Formatter},
};

/// Error types
#[derive(Debug)]
pub enum Error {
    /// pkcs1-related errors
    Pkcs1(Pkcs1Error),
    /// The client is not yet ready to receive data.
    NotReady,
    /// The connection has been lost due to an error during transmission.
    SocketDied,
    /// Request timed out
    Timeout,
    /// payload-related errors
    Payload(PayloadError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Pkcs1(error) => error.fmt(f),
            Self::Payload(error) => error.fmt(f),
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

error_impl_from!(Pkcs1, Payload);
