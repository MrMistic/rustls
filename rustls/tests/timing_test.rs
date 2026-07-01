#![cfg(feature = "timing")]

//! Integration tests for the timing instrumentation feature.
//!
//! These tests validate end-to-end behavior of the timing checkpoint system
//! across various handshake scenarios.

use std::sync::{Arc, Mutex};

use rustls::client::ClientConnection;
use rustls::crypto::aws_lc_rs as provider;
use rustls::server::ServerConnection;
use rustls::timing::{Role, TimingCheckpoint, TimingSubscriber};
use rustls::{ClientConfig, RootCertStore};
use rustls_test::*;

/// A recording subscriber that captures all checkpoints into a shared Vec.
#[derive(Clone)]
struct RecordingSubscriber {
    checkpoints: Arc<Mutex<Vec<TimingCheckpoint>>>,
}

impl RecordingSubscriber {
    fn new() -> Self {
        Self {
            checkpoints: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn checkpoints(&self) -> Vec<TimingCheckpoint> {
        self.checkpoints.lock().unwrap().clone()
    }
}

impl TimingSubscriber for RecordingSubscriber {
    fn on_timing_checkpoint(&self, checkpoint: &TimingCheckpoint) {
        self.checkpoints
            .lock()
            .unwrap()
            .push(checkpoint.clone());
    }
}

/// Happy-path TLS 1.3 test (Requirements 10.1–10.5, 11.1):
/// Run an in-memory handshake with client + server recorders; assert START first,
/// END last, core messages present, timestamps non-decreasing.
#[test]
fn happy_path_tls13_handshake() {
    let client_subscriber = RecordingSubscriber::new();
    let server_subscriber = RecordingSubscriber::new();

    let crypto_provider = provider::default_provider();

    let mut server_config = make_server_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    server_config.set_timing_subscriber(Arc::new(server_subscriber.clone()));

    let mut client_config = make_client_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    client_config.set_timing_subscriber(Arc::new(client_subscriber.clone()));

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);
    let mut client =
        ClientConnection::new(client_config, server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    do_handshake(&mut client, &mut server);

    let client_cps = client_subscriber.checkpoints();
    let server_cps = server_subscriber.checkpoints();

    // Both sides must have checkpoints
    assert!(!client_cps.is_empty(), "client should have checkpoints");
    assert!(!server_cps.is_empty(), "server should have checkpoints");

    // NEGOTIATE_START must be first on both sides
    assert_eq!(
        client_cps[0].name, "NEGOTIATE_START",
        "client first checkpoint must be NEGOTIATE_START"
    );
    assert_eq!(
        server_cps[0].name, "NEGOTIATE_START",
        "server first checkpoint must be NEGOTIATE_START"
    );

    // NEGOTIATE_START has timestamp_ns == 0
    assert_eq!(client_cps[0].timestamp_ns, 0);
    assert_eq!(server_cps[0].timestamp_ns, 0);

    // NEGOTIATE_END must be present. It is the last *handshake* checkpoint,
    // but post-handshake messages (e.g. NewSessionTicket) may follow.
    assert!(
        client_cps.iter().any(|cp| cp.name == "NEGOTIATE_END"),
        "client must have NEGOTIATE_END"
    );
    assert!(
        server_cps.iter().any(|cp| cp.name == "NEGOTIATE_END"),
        "server must have NEGOTIATE_END"
    );

    // NEGOTIATE_END must come after NEGOTIATE_START
    let client_end_idx = client_cps
        .iter()
        .position(|cp| cp.name == "NEGOTIATE_END")
        .unwrap();
    let server_end_idx = server_cps
        .iter()
        .position(|cp| cp.name == "NEGOTIATE_END")
        .unwrap();
    assert!(client_end_idx > 0);
    assert!(server_end_idx > 0);

    // Core messages present on client side: SERVER_HELLO, SERVER_FINISHED
    let client_names: Vec<&str> = client_cps.iter().map(|cp| cp.name.as_str()).collect();
    assert!(
        client_names.contains(&"SERVER_HELLO"),
        "client should see SERVER_HELLO, got: {:?}",
        client_names
    );
    assert!(
        client_names.contains(&"SERVER_FINISHED"),
        "client should see SERVER_FINISHED, got: {:?}",
        client_names
    );

    // Core messages present on server side: CLIENT_HELLO, CLIENT_FINISHED
    let server_names: Vec<&str> = server_cps.iter().map(|cp| cp.name.as_str()).collect();
    assert!(
        server_names.contains(&"CLIENT_HELLO"),
        "server should see CLIENT_HELLO, got: {:?}",
        server_names
    );
    assert!(
        server_names.contains(&"CLIENT_FINISHED"),
        "server should see CLIENT_FINISHED, got: {:?}",
        server_names
    );

    // Timestamps must be non-decreasing on both sides
    for window in client_cps.windows(2) {
        assert!(
            window[1].timestamp_ns >= window[0].timestamp_ns,
            "client timestamps not non-decreasing: {} ({}) -> {} ({})",
            window[0].name,
            window[0].timestamp_ns,
            window[1].name,
            window[1].timestamp_ns,
        );
    }
    for window in server_cps.windows(2) {
        assert!(
            window[1].timestamp_ns >= window[0].timestamp_ns,
            "server timestamps not non-decreasing: {} ({}) -> {} ({})",
            window[0].name,
            window[0].timestamp_ns,
            window[1].name,
            window[1].timestamp_ns,
        );
    }

    // Roles must be correct
    for cp in &client_cps {
        assert_eq!(cp.role, Role::Client);
    }
    for cp in &server_cps {
        assert_eq!(cp.role, Role::Server);
    }
}

/// Error path test (Requirements 1.6, 2.5):
/// Force handshake failure with untrusted cert; assert no NEGOTIATE_END on the
/// failing side; any prior checkpoints retained.
#[test]
fn error_path_no_negotiate_end() {
    let client_subscriber = RecordingSubscriber::new();

    let crypto_provider = provider::default_provider();

    // Server uses Rsa2048 certs
    let server_config = make_server_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );

    // Client config with an empty root store (won't trust the server cert)
    let mut client_config = ClientConfig::builder_with_provider(crypto_provider.clone().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    client_config.set_timing_subscriber(Arc::new(client_subscriber.clone()));

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);
    let mut client =
        ClientConnection::new(client_config, server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    // Drive the handshake — expect it to fail
    let result = do_handshake_until_error(&mut client, &mut server);
    assert!(result.is_err(), "handshake should fail with untrusted cert");

    let client_cps = client_subscriber.checkpoints();

    // The client should NOT have a NEGOTIATE_END (error path — Requirement 1.6, 2.5)
    let has_negotiate_end = client_cps.iter().any(|cp| cp.name == "NEGOTIATE_END");
    assert!(
        !has_negotiate_end,
        "failing side should NOT have NEGOTIATE_END, got: {:?}",
        client_cps.iter().map(|cp| &cp.name).collect::<Vec<_>>()
    );

    // Any prior checkpoints should still be retained (subscriber received them)
    // The client should at least have NEGOTIATE_START (since it processes
    // the ServerHello before discovering the untrusted cert)
    assert!(
        !client_cps.is_empty(),
        "failing side should retain any prior checkpoints"
    );
    assert_eq!(
        client_cps[0].name, "NEGOTIATE_START",
        "first checkpoint should still be NEGOTIATE_START"
    );
}

/// No-subscriber test (Requirements 9.1–9.3):
/// Feature on, no subscriber; assert handshake succeeds normally with no panics.
#[test]
fn no_subscriber_handshake_succeeds() {
    let crypto_provider = provider::default_provider();

    // Don't call set_timing_subscriber — leave it as None
    let server_config = make_server_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    let client_config = make_client_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);
    let mut client =
        ClientConnection::new(client_config, server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    // Handshake should complete without panicking
    do_handshake(&mut client, &mut server);

    // Verify handshake actually completed
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
}

/// TLS 1.2 completion test (Requirements 11.2, 11.3):
/// With tls12 feature enabled, run a TLS 1.2 handshake; assert successful completion.
/// Do not assert specific checkpoint names/order.
#[cfg(feature = "tls12")]
#[test]
fn tls12_handshake_completes() {
    let client_subscriber = RecordingSubscriber::new();
    let server_subscriber = RecordingSubscriber::new();

    let crypto_provider = provider::default_provider();

    let mut server_config = make_server_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS12],
        &crypto_provider,
    );
    server_config.set_timing_subscriber(Arc::new(server_subscriber.clone()));

    let mut client_config = make_client_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS12],
        &crypto_provider,
    );
    client_config.set_timing_subscriber(Arc::new(client_subscriber.clone()));

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);
    let mut client =
        ClientConnection::new(client_config, server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    do_handshake(&mut client, &mut server);

    // Verify handshake completed
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());

    // Verify that checkpoints were collected (don't assert specific names/order)
    let client_cps = client_subscriber.checkpoints();
    let server_cps = server_subscriber.checkpoints();
    assert!(
        !client_cps.is_empty(),
        "client should have received some checkpoints for TLS 1.2"
    );
    assert!(
        !server_cps.is_empty(),
        "server should have received some checkpoints for TLS 1.2"
    );
}

/// Re-registration test (Requirement 8.6):
/// Register subscriber A then B on config; run handshake; assert only B received checkpoints.
#[test]
fn re_registration_only_last_subscriber_receives() {
    let subscriber_a = RecordingSubscriber::new();
    let subscriber_b = RecordingSubscriber::new();

    let crypto_provider = provider::default_provider();

    let mut client_config = make_client_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    // Register A first, then replace with B
    client_config.set_timing_subscriber(Arc::new(subscriber_a.clone()));
    client_config.set_timing_subscriber(Arc::new(subscriber_b.clone()));

    let server_config = make_server_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);
    let mut client =
        ClientConnection::new(client_config, server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    do_handshake(&mut client, &mut server);

    let a_checkpoints = subscriber_a.checkpoints();
    let b_checkpoints = subscriber_b.checkpoints();

    // Subscriber A should have received NO checkpoints (it was replaced)
    assert!(
        a_checkpoints.is_empty(),
        "subscriber A should have no checkpoints after being replaced, got: {:?}",
        a_checkpoints.iter().map(|cp| &cp.name).collect::<Vec<_>>()
    );

    // Subscriber B should have received checkpoints
    assert!(
        !b_checkpoints.is_empty(),
        "subscriber B should have received checkpoints"
    );
    assert_eq!(
        b_checkpoints[0].name, "NEGOTIATE_START",
        "subscriber B first checkpoint should be NEGOTIATE_START"
    );
}

/// Demonstration: print the per-message timing breakdown for a TLS 1.3 handshake.
///
/// Run with output visible:
///   cargo test -p rustls --features timing --test timing_test -- --nocapture print_handshake_timing
fn print_breakdown(label: &str, cps: &[TimingCheckpoint]) {
    println!("\n=== {label} checkpoints ({} total) ===", cps.len());
    println!(
        "{:<22} {:>14} {:>14}  {:>5}",
        "NAME", "timestamp_ns", "delta_ns", "role"
    );
    let mut prev: Option<u64> = None;
    for cp in cps {
        let delta = prev
            .map(|p| cp.timestamp_ns.saturating_sub(p))
            .unwrap_or(0);
        println!(
            "{:<22} {:>14} {:>14}  {:>5}",
            cp.name,
            cp.timestamp_ns,
            delta,
            cp.role.as_u8()
        );
        prev = Some(cp.timestamp_ns);
    }

    // The handshake span is NEGOTIATE_START .. NEGOTIATE_END.
    let start = cps
        .iter()
        .find(|c| c.name == "NEGOTIATE_START")
        .map(|c| c.timestamp_ns);
    let end = cps
        .iter()
        .find(|c| c.name == "NEGOTIATE_END")
        .map(|c| c.timestamp_ns);
    if let (Some(s), Some(e)) = (start, end) {
        println!("--> total handshake span: {} ns", e - s);
    }
}

#[test]
fn print_handshake_timing() {
    let client_subscriber = RecordingSubscriber::new();
    let server_subscriber = RecordingSubscriber::new();

    let crypto_provider = provider::default_provider();

    let mut server_config = make_server_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    server_config.set_timing_subscriber(Arc::new(server_subscriber.clone()));

    let mut client_config = make_client_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    client_config.set_timing_subscriber(Arc::new(client_subscriber.clone()));

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);
    let mut client =
        ClientConnection::new(client_config, server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    do_handshake(&mut client, &mut server);

    print_breakdown("CLIENT (role=1)", &client_subscriber.checkpoints());
    print_breakdown("SERVER (role=0)", &server_subscriber.checkpoints());
}

/// Diagnostic: demonstrates that a RESUMED TLS 1.3 handshake emits no
/// SERVER_CERT / SERVER_CERT_VERIFY on the client side, because the server
/// sends no certificate flight on resumption. This explains the "missing
/// cert checkpoints" a harness sees when it reuses one ClientConfig (with its
/// default in-memory session store) across iterations: iteration 1 is a full
/// handshake, every later iteration resumes.
///
///   cargo test -p rustls --features timing --test timing_test -- --nocapture full_vs_resumed_checkpoints
#[test]
fn full_vs_resumed_checkpoints() {
    let crypto_provider = provider::default_provider();

    let server_config = Arc::new(make_server_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    ));

    // One client config, reused across both handshakes — this is what a harness
    // naturally does, and it enables resumption via the default session store.
    let client_config = Arc::new(make_client_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    ));

    let names = |cps: &[TimingCheckpoint]| -> Vec<String> {
        cps.iter().map(|c| c.name.clone()).collect()
    };

    // --- Handshake 1: full ---
    let rec1 = RecordingSubscriber::new();
    {
        let mut cc = (*client_config).clone();
        cc.set_timing_subscriber(Arc::new(rec1.clone()));
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(cc), &server_config);
        do_handshake(&mut client, &mut server);
    }

    // --- Handshake 2: resumed (same client_config, so the ticket is stored) ---
    let rec2 = RecordingSubscriber::new();
    {
        let mut cc = (*client_config).clone();
        cc.set_timing_subscriber(Arc::new(rec2.clone()));
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(cc), &server_config);
        do_handshake(&mut client, &mut server);
    }

    println!("\nHANDSHAKE 1 (full)    client: {:?}", names(&rec1.checkpoints()));
    println!("HANDSHAKE 2 (resumed) client: {:?}", names(&rec2.checkpoints()));
}
