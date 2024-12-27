use serde::{Serialize, Deserialize};

/// State of the connection.
pub enum ConnecitonState {
    /// A conneciton that has not yet been handled.
    Socket,
    /// An authorized connection that waiting for being converted to cmd or forward socket.
    Authorized { token: Token },
    /// A connection, shares/receives ports or sends commands.
    Handled { connection_type: ConnectionType },
}

/// Connection that awaiting or sending commands or forwarding ports.
pub enum ConnectionType {
    /// Encrypted management connection.
    Cmd { token: Token },
    /// A TCP connection that forwards port.
    TcpFwd {
        /// Indicates that the connection shares a port or receives one.
        kind: FwdKind,
        /// forwarded port
        port: u32,
        /// unique id of the routing request
        id: u64,
    },
}

/// Type of the port forwarding connection.
pub enum FwdKind {
    /// The connection shares its port.
    Share,
    /// The connection receives a port.
    Receive,
}

/// Connection authentication token
#[derive(Serialize, Deserialize)]
pub struct Token {
    pub hostname: String,
    pub permission_level: util::PermissionLevel,
}
