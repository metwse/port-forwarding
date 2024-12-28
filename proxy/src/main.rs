use dotenv::dotenv;
use proxy::ServerBuilder;

#[tokio::main]
async fn main() {
    dotenv().ok();
    util::env![CERT, DATABASE_URL, HOST];

    ServerBuilder::new()
        .private_key_file(*CERT)
        .sqlite_database(*DATABASE_URL)
        .await
        .build()
        .serve(*HOST)
        .await;
}
