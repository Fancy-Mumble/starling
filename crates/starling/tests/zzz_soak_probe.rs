//! Scratch: why does the soak's virtual client get disconnected?
#![allow(unused_crate_dependencies, reason = "scratch")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::excessive_nesting,
    reason = "scratch"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use starling_harness::{Client, Deployment, TempDir, handshake};
use starling_proto::proto::tcp;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "scratch"]
async fn why_is_the_client_dropped() {
    let dir = TempDir::new("soak-probe");
    let deployment = Deployment::start(dir.path()).await;
    let mut channels = Vec::new();
    for i in 0..4 {
        channels.push(deployment.create_channel(&format!("probe-{i}")).await);
    }
    let channels = Arc::new(channels);
    let stop = Arc::new(AtomicBool::new(false));

    let mut tasks = Vec::new();
    for id in 0..6_u64 {
        let channels = Arc::clone(&channels);
        let stop = Arc::clone(&stop);
        let port = deployment.port;
        tasks.push(tokio::spawn(async move {
            let mut client = Client::connect(port).await;
            let session = handshake(&mut client, &format!("probe-{id}")).await;
            let mut rounds = 0_u32;
            while !stop.load(Ordering::Relaxed) {
                let target = channels[(rounds as usize + id as usize) % channels.len()];
                client
                    .send(
                        9,
                        &tcp::UserState {
                            session: Some(session),
                            channel_id: Some(target),
                            ..tcp::UserState::default()
                        },
                    )
                    .await;
                client
                    .send(
                        11,
                        &tcp::TextMessage {
                            message: "s".repeat(32),
                            channel_id: vec![channels[0]],
                            ..tcp::TextMessage::default()
                        },
                    )
                    .await;
                rounds += 1;
                while client.next_frame(Duration::from_millis(50)).await.is_some() {}
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            rounds
        }));
    }

    tokio::time::sleep(Duration::from_secs(25)).await;
    let overview = deployment.overview().await;
    for service in &overview.services {
        for load in &service.load {
            if load.name.contains("connection") || load.name.contains("session") {
                println!(
                    "  gauge {}.{} used={}",
                    service.service, load.name, load.used
                );
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    for task in tasks {
        match tokio::time::timeout(Duration::from_secs(20), task).await {
            Ok(Ok(rounds)) => println!("client finished after {rounds} rounds"),
            Ok(Err(error)) => println!(
                "client PANICKED: {}",
                starling_harness::panic_message(error)
            ),
            Err(_) => println!("client would not stop"),
        }
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let overview = deployment.overview().await;
    for service in &overview.services {
        for load in &service.load {
            if load.name.contains("connection") || load.name.contains("session") {
                println!(
                    "  after: gauge {}.{} used={}",
                    service.service, load.name, load.used
                );
            }
        }
    }

    for record in deployment.records() {
        let m = &record.message;
        if m.contains("text message")
            || m.contains("entered a channel")
            || m.contains("permission denied")
        {
            continue;
        }
        println!("  [{:?}] {} {:?}", record.severity, m, record.fields);
    }
    deployment.stop_allowing(&[]).await;
}
