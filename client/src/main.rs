use client::Client;

#[tokio::main]
async fn main() {
    Client::connect("localhost:4040", "../env/public.pem", "1234").await;
}
