//! A mempool backend that accepts a connection and never answers must not
//! hang the caller: the anchoring locks are held across these calls.

use std::time::Duration;

use solid_pod_rs::bitcoin_tx::MempoolBroadcast;
use solid_pod_rs_server::mempool::MempoolHttpClient;

/// A listener that accepts connections and then says nothing.
async fn silent_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    (url, task)
}

#[tokio::test]
async fn silent_backend_times_out_instead_of_hanging() {
    let (url, _server) = silent_server().await;
    let client = MempoolHttpClient::new(url)
        .with_timeouts(Duration::from_millis(200), Duration::from_millis(500));
    let outer = Duration::from_secs(5);
    let broadcast = tokio::time::timeout(outer, client.broadcast_tx("00"))
        .await
        .expect("broadcast hung past the client timeout");
    assert!(broadcast.is_err());
    let exists = tokio::time::timeout(outer, client.transaction_exists(&"aa".repeat(32)))
        .await
        .expect("presence check hung past the client timeout");
    assert!(exists.is_err(), "a timeout is ambiguous, not a definite no");
}
