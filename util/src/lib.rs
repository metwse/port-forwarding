use serde::{Deserialize, Serialize};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

// loads environment variables to &'static str
#[macro_export]
macro_rules! env {
    ($($name: ident),*) => {
        lazy_static::lazy_static! {
            $(
                static ref $name: &'static str = Box::leak(
                    std::env::var(stringify!($name))
                        .expect(&format!("Cannot find environment variable {}", stringify!($name))[..])
                        .into_boxed_str()
                );
            )*
        }
    };
}

/// Command interface for clients/servers
#[derive(Serialize, Deserialize, Debug)]
pub enum Cmd {
    Noop,
    Authenticate {
        token: Vec<u8>,
    },
    GetPort {
        hostname: String,
        port: u32,
    },
    SharePort {
        port: u32,
        id: u64,
    },
    ListClients {
        after: String,
        limit: u64,
    },
    AddClient {
        username: String,
        token: String,
        permission_level: PermissionLevel,
    },
    RemoveClient {
        username: String,
    },
}

/// Permission level of the client
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum PermissionLevel {
    Admin(u32),
    Standart,
    Node,
    Any,
}

impl Cmd {
    /// Checks required minimum permission level for executing the command.
    pub fn minimum_permission_level(&self) -> PermissionLevel {
        match self {
            Self::Noop => PermissionLevel::Any,
            Self::Authenticate { .. } => PermissionLevel::Any,
            Self::GetPort { .. } => PermissionLevel::Standart,
            Self::SharePort { .. } => PermissionLevel::Node,
            Self::ListClients { .. } => PermissionLevel::Admin(0),
            Self::AddClient {
                permission_level, ..
            } => match permission_level {
                PermissionLevel::Admin(admin_level) => PermissionLevel::Admin(admin_level + 1),
                _ => PermissionLevel::Admin(0),
            },
            Self::RemoveClient { .. } => PermissionLevel::Admin(0),
        }
    }
}

impl PermissionLevel {
    /// Checks whether `self` is at least `other`'s level.
    pub fn at_least(&self, other: &Self) -> bool {
        if let Self::Admin(_) = self {
            if !matches!(other, Self::Admin(_)) {
                return true
            }
        }

        match (other, self) {
            (Self::Admin(other_level), Self::Admin(level)) => *other_level < *level,
            (Self::Any, _) => true,
            _ => {
                other == self
            },
        }
    }
}


pub async fn copy_bidirectional((mut r, mut w): (OwnedReadHalf, OwnedWriteHalf), (mut target_r, mut target_w): (OwnedReadHalf, OwnedWriteHalf)) {
    tokio::join!{
        async move {
            loop {
                if tokio::io::copy(&mut target_r, &mut w).await.is_err() {
                    break;
                }
            }
        },
        async move {
            loop {
                if tokio::io::copy(&mut r, &mut target_w).await.is_err() {
                    break;
                }
            }
        }
    };
}
