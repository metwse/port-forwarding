use super::Server;
use crate::connection::Connection;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
};

impl Server {
    pub async fn tcp_handshake(&self, stream: &mut TcpStream) -> Option<Connection> {
        let (read_half, _) = stream.split();
        let mut br = BufReader::new(read_half);
        let mut first_line = String::new();

        br.read_line(&mut first_line).await.ok()?;

        todo!()
    }
}