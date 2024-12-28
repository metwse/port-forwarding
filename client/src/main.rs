use client::Client;
use dotenv::dotenv;

#[tokio::main]
async fn main() {
    dotenv().ok();
    util::env![CERT, TOKEN, HOST];

    Client::connect(*HOST, *CERT, *TOKEN).await;
}
