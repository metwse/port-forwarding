/// State of the connection.
#[derive(Debug)]
pub enum ConnectionState {
    /// A conneciton that has not yet been authorized.
    Socket,
    /// An authorized connection that waiting for being converted to cmd or forward socket.
    Authorized {
        hostname: String,
        permission_level: util::PermissionLevel,
    },
    /// A connection, shares/receives ports or sends commands.
    PortForward {
        hostname: String,
        /// Indicates that the connection shares a port or receives one.
        kind: ForwardKind,
        /// forwarded port
        port: u32,
        /// unique id of the routing request
        id: u64,
    },
}

/// Type of the port forwarding connection.
#[derive(Debug)]
pub enum ForwardKind {
    /// The connection shares its port.
    Share,
    /// The connection receives a port.
    Receive,
}
