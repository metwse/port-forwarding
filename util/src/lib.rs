/// Command interface for clients/servers.
pub enum Cmd {
    GetPort { hostname: u64, port: u32 },
    SharePort { id: u64, port: u32 },
    ListNodes { after: String, limit: u64 },
    AddNode { hostname: String },
    DeletoNode { hostname: String },
    ListClients { after: String, limit: u64 },
    AddClient { username: String, is_admin: bool },
    RemoveClient { username: String },
}
