use proxy::ServerBuilder;

#[tokio::main]
async fn main() {
    ServerBuilder::new()
        .private_key_file("../env/private.pem")
        .sqlite_database("sqlite://server.db")
        .await
        .build()
        .serve("0.0.0.0:4040")
        .await;
}
