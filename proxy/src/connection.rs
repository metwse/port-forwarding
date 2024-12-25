/// Connection that awaiting or sending commands or forwarding ports.
pub enum Connection {
    /// Encrypted management connection.
    Cmd {
        /// The scope that the connection is authorized to do.
        token: CmdToken,
    },
    /// A TCP connection that forwards port.
    TcpFwd {
        /// Indicates that the connection shares a port or receives one.
        kind: FwdKind,
        /// forwarded port
        port: u32,
        /// unique id of the TCP connection
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

/// Permissions of the TCP connection.
pub enum CmdToken {
    /// Node connection that serves port.
    Node {
        /// hostname of the node
        hostname: String,
    },
    /// A conneciton can receive ports.
    StandardClient {
        /// hostname of the client
        username: String,
    },
    /// A conneciton can manage nodes and receive ports.
    AdminClient {
        /// username of the client
        username: String,
    },
}
