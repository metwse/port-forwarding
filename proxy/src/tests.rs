#[tokio::test]
async fn server() {
    use crate::*;

    ServerBuilder::new()
        .private_key_file("./env/private.pem")
        .build()
        .serve("0.0.0.0:8080")
        .await;
}
