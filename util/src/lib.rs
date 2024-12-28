use serde::{Deserialize, Serialize};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

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
    ListNodes {
        after: String,
        limit: u64,
    },
    AddNode {
        hostname: String,
    },
    RemoveNode {
        hostname: String,
    },
    ListClients {
        after: String,
        limit: u64,
    },
    AddClient {
        username: String,
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
            Self::ListNodes { .. } => PermissionLevel::Standart,
            Self::AddNode { .. } => PermissionLevel::Admin(0),
            Self::RemoveNode { .. } => PermissionLevel::Admin(0),
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
        if other == self {
            return true
        }

        match (other, self) {
            (Self::Admin(other_level), Self::Admin(level)) => *other_level >= *level,
            (Self::Any, _) => true,
            _ => false,
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
