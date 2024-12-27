use serde::{Deserialize, Serialize};

/// Command interface for clients/servers
#[derive(Serialize, Deserialize)]
pub enum Cmd {
    GetPort {
        hostname: u64,
        port: u32,
    },
    SharePort {
        id: u64,
        port: u32,
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
#[derive(Serialize, Deserialize)]
pub enum PermissionLevel {
    Admin(u32),
    Standart,
    Node,
}

impl Cmd {
    /// Checks required minimum permission level for executing the command.
    pub fn minimum_permission_level(&self) -> PermissionLevel {
        match self {
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
        match (other, self) {
            (Self::Admin(other_level), Self::Admin(level)) => *other_level >= *level,
            _ => false,
        }
    }
}

pub mod mtls;
