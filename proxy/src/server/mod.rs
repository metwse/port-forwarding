/// Server database utils.
pub mod database;

pub mod handle_connection;

use ptls::Ptls;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::{
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, ToSocketAddrs,
    },
    sync::Mutex,
};

/// Server builer struct.
#[derive(Default)]
pub struct ServerBuilder {
    private_key: Option<RsaPrivateKey>,
    sqlite: Option<SqlitePool>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn private_key(mut self, private_key: &str) -> Self {
        self.private_key = Some(
            DecodeRsaPrivateKey::from_pkcs1_pem(private_key).expect("Cannot decode pkcs1 pem"),
        );
        self
    }

    pub fn private_key_file(mut self, private_key_file: &str) -> Self {
        self.private_key = Some(
            DecodeRsaPrivateKey::read_pkcs1_pem_file(private_key_file)
                .expect("Cannot decode pkcs1 pem"),
        );
        self
    }

    pub async fn sqlite_database(mut self, url: &str) -> Self {
        let options = SqliteConnectOptions::from_str(url)
            .unwrap()
            .create_if_missing(true);

        let database = SqlitePool::connect_with(options)
            .await
            .expect("Cannot connect sqlite database");

        sqlx::migrate!("./migrations").run(&database).await.ok();

        self.sqlite = Some(database);
        self
    }

    pub fn build(mut self) -> Arc<Server> {
        Arc::new(Server {
            private_key: self.private_key.take().expect("Private key is not given"),
            sqlite: self
                .sqlite
                .take()
                .expect("No sqlite database has been given"),
            forward_connections: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
        })
    }
}

/// Port forwarding proxy server.
pub struct Server {
    private_key: RsaPrivateKey,
    sqlite: SqlitePool,
    forward_connections: Mutex<HashMap<u64, (OwnedReadHalf, OwnedWriteHalf)>>,
    connections: Mutex<HashMap<String, Arc<Ptls<OwnedReadHalf, OwnedWriteHalf>>>>,
}

impl Server {
    /// Serves the proxy server.
    pub async fn serve<T: ToSocketAddrs>(self: Arc<Self>, addr: T) -> ! {
        let listener = TcpListener::bind(addr).await.unwrap();

        //let blob = bincode::serialize(&util::PermissionLevel::Admin(u32::MAX)).unwrap();
        //sqlx::query_scalar!("INSERT INTO clients SELECT 'su', ?, '1234';", blob)
        //    .fetch_optional(&self.sqlite)
        //    .await
        //    .unwrap();

        loop {
            let socket = match listener.accept().await {
                Ok((socket, _)) => socket,
                Err(_) => continue,
            };

            if socket.set_ttl(16).is_err() {
                continue;
            }

            let this = Arc::clone(&self);
            tokio::spawn(this.handle_connection(socket));
        }
    }
}
