use super::*;

#[tokio::test]
async fn mtls() {
    use rand::thread_rng;

    let mut rng = thread_rng();

    let server_private = RsaPrivateKey::new(&mut rng, 512).unwrap();
    let server_public = RsaPublicKey::from(&server_private);
    let client_private = RsaPrivateKey::new(&mut rng, 512).unwrap();

    let server = tokio::net::TcpListener::bind("localhost:7811")
        .await
        .unwrap();

    let (tcp_stream, accept) = tokio::join!(TcpStream::connect("localhost:7811"), server.accept());
    let client = tcp_stream.unwrap();
    let (peer, _) = accept.unwrap();

    let mut client_mtls = Mtls::new(client, client_private);
    client_mtls.set_public_key(server_public);

    let mut server_handler_mtls = Mtls::new(peer, server_private);
    let (server_handshake_result, client_send_result) = tokio::join!(
        server_handler_mtls.handshake(),
        client_mtls.send_public_key()
    );
    server_handshake_result.expect("Server could not retrieve certificate");
    client_send_result.expect("Client could not send certificate");

    let msg = b"a repetitive message".repeat(16);

    client_mtls.send(&msg).await.unwrap();
    server_handler_mtls.send(&msg).await.unwrap();

    let server_received = server_handler_mtls.receive().await.unwrap();
    let client_received = client_mtls.receive().await.unwrap();

    assert_eq!(msg.len(), server_received.len());
    assert_eq!(msg.len(), client_received.len());
}
