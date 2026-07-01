#![cfg(feature = "timing")]

//! Property-based tests for the timing instrumentation feature.
//!
//! These tests validate correctness properties of the timing checkpoint system
//! using real in-memory TLS 1.3 handshakes.

use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use rustls::client::ClientConnection;
use rustls::crypto::aws_lc_rs as provider;
use rustls::server::ServerConnection;
use rustls::timing::{Role, TimingCheckpoint, TimingSubscriber};
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

/// Helper: perform a TLS 1.3 in-memory handshake with recording subscribers on both sides.
/// Returns (client_checkpoints, server_checkpoints).
fn do_tls13_handshake_with_subscribers() -> (Vec<TimingCheckpoint>, Vec<TimingCheckpoint>) {
    let client_subscriber = RecordingSubscriber::new();
    let server_subscriber = RecordingSubscriber::new();

    let crypto_provider = provider::default_provider();

    // Build server config using rustls_test helpers
    let mut server_config = make_server_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    server_config.set_timing_subscriber(Arc::new(server_subscriber.clone()));

    // Build client config using rustls_test helpers
    let mut client_config = make_client_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    client_config.set_timing_subscriber(Arc::new(client_subscriber.clone()));

    // Create connections
    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);
    let mut client =
        ClientConnection::new(client_config, server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    // Drive the handshake to completion
    do_handshake(&mut client, &mut server);

    (client_subscriber.checkpoints(), server_subscriber.checkpoints())
}

// Feature: rustls-timing-instrumentation, Property 4: Role is constant per connection and correctly encoded
proptest! {
    /// Property 4: Role is constant per connection and correctly encoded
    ///
    /// **Validates: Requirements 2.6, 3.2, 3.3**
    ///
    /// Over captured sequences for both client and server roles: assert every
    /// checkpoint carries the same role, and role matches the connection's side encoding.
    #[test]
    fn prop_role_is_constant_per_connection_and_correctly_encoded(_ in 0..10u32) {
        let (client_checkpoints, server_checkpoints) = do_tls13_handshake_with_subscribers();

        // Client side: every checkpoint must have Role::Client (as_u8() == 1)
        assert!(!client_checkpoints.is_empty(), "client must have at least one checkpoint");
        for cp in &client_checkpoints {
            prop_assert_eq!(
                cp.role,
                Role::Client,
                "Client checkpoint '{}' has wrong role: expected Client, got {:?}",
                cp.name,
                cp.role
            );
            prop_assert_eq!(
                cp.role.as_u8(),
                1u8,
                "Client role as_u8() should be 1, got {}",
                cp.role.as_u8()
            );
        }

        // Server side: every checkpoint must have Role::Server (as_u8() == 0)
        assert!(!server_checkpoints.is_empty(), "server must have at least one checkpoint");
        for cp in &server_checkpoints {
            prop_assert_eq!(
                cp.role,
                Role::Server,
                "Server checkpoint '{}' has wrong role: expected Server, got {:?}",
                cp.name,
                cp.role
            );
            prop_assert_eq!(
                cp.role.as_u8(),
                0u8,
                "Server role as_u8() should be 0, got {}",
                cp.role.as_u8()
            );
        }
    }
}


// Feature: rustls-timing-instrumentation, Property 2: Timestamps are monotonic non-decreasing
// **Validates: Requirements 4.2, 6.4, 10.5**

/// Helper: perform a TLS 1.3 in-memory handshake with a given key type and
/// recording subscribers on both sides. Returns (client_checkpoints, server_checkpoints).
fn do_tls13_handshake_with_key_type(kt: KeyType) -> (Vec<TimingCheckpoint>, Vec<TimingCheckpoint>) {
    let client_subscriber = RecordingSubscriber::new();
    let server_subscriber = RecordingSubscriber::new();

    let crypto_provider = provider::default_provider();

    let mut server_config = make_server_config_with_versions(
        kt,
        &[&rustls::version::TLS13],
        &crypto_provider,
    );
    server_config.set_timing_subscriber(Arc::new(server_subscriber.clone()));

    let mut client_config = make_client_config_with_versions(
        kt,
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

    (client_subscriber.checkpoints(), server_subscriber.checkpoints())
}

/// Assert that all timestamps in a checkpoint sequence are monotonically non-decreasing.
fn assert_monotonic_timestamps(
    checkpoints: &[TimingCheckpoint],
    context: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    prop_assert!(
        !checkpoints.is_empty(),
        "{}: expected non-empty checkpoint sequence",
        context,
    );
    for i in 0..checkpoints.len() - 1 {
        prop_assert!(
            checkpoints[i + 1].timestamp_ns >= checkpoints[i].timestamp_ns,
            "{}: timestamp at index {} ({}) is less than timestamp at index {} ({}). \
             Names: [{}] -> [{}]",
            context,
            i + 1,
            checkpoints[i + 1].timestamp_ns,
            i,
            checkpoints[i].timestamp_ns,
            checkpoints[i].name,
            checkpoints[i + 1].name,
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Property 2: Timestamps are monotonic non-decreasing.
    ///
    /// Over captured handshake sequences (varying configs via key type selection),
    /// assert each adjacent pair `timestamp_ns[i+1] >= timestamp_ns[i]`.
    ///
    /// **Validates: Requirements 4.2, 6.4, 10.5**
    #[test]
    fn prop_timestamps_monotonic_nondecreasing(kt_index in 0usize..3) {
        // Feature: rustls-timing-instrumentation, Property 2: Timestamps are monotonic non-decreasing
        let kt = match kt_index {
            0 => KeyType::Rsa2048,
            1 => KeyType::EcdsaP256,
            2 => KeyType::EcdsaP384,
            _ => unreachable!(),
        };

        let (client_cps, server_cps) = do_tls13_handshake_with_key_type(kt);

        // Assert monotonicity for client-side checkpoints
        assert_monotonic_timestamps(
            &client_cps,
            &format!("client (kt={:?})", kt),
        )?;

        // Assert monotonicity for server-side checkpoints
        assert_monotonic_timestamps(
            &server_cps,
            &format!("server (kt={:?})", kt),
        )?;
    }
}

// Feature: rustls-timing-instrumentation, Property 3: Anchor ordering, uniqueness, and zero epoch
proptest! {
    /// Property 3: Anchor ordering, uniqueness, and zero epoch.
    ///
    /// **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 6.3, 10.1, 10.2, 10.4**
    ///
    /// Over captured TLS 1.3 handshake sequences: assert exactly one NEGOTIATE_START
    /// as first element with `timestamp_ns == 0`, exactly one NEGOTIATE_END as last
    /// handshake element, all message checkpoints strictly between the anchors.
    #[test]
    fn prop_anchor_ordering_uniqueness_and_zero_epoch(_ in 0..10u32) {
        let (client_cps, server_cps) = do_tls13_handshake_with_subscribers();

        // Verify the property for both client-side and server-side sequences.
        // The full captured stream may contain post-handshake messages (e.g.
        // NewSessionTicket) delivered after NEGOTIATE_END. The property applies
        // to the handshake sequence bounded by the anchors.
        assert_anchor_property(&client_cps, "client")?;
        assert_anchor_property(&server_cps, "server")?;
    }
}

/// Assert Property 3 invariants on a checkpoint sequence.
///
/// The property considers the handshake sequence from NEGOTIATE_START through
/// NEGOTIATE_END (inclusive). Post-handshake messages (like NewSessionTicket)
/// that are emitted after NEGOTIATE_END are not part of the handshake sequence
/// and are excluded from the ordering assertion.
fn assert_anchor_property(
    checkpoints: &[TimingCheckpoint],
    side_label: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    // Must have at least some checkpoints
    prop_assert!(
        !checkpoints.is_empty(),
        "{}: expected non-empty checkpoint sequence",
        side_label
    );

    // (c) There is exactly one NEGOTIATE_START in the full sequence
    let start_count = checkpoints
        .iter()
        .filter(|cp| cp.name == "NEGOTIATE_START")
        .count();
    prop_assert_eq!(
        start_count,
        1,
        "{}: expected exactly one NEGOTIATE_START, got {}",
        side_label,
        start_count
    );

    // (d) There is exactly one NEGOTIATE_END in the full sequence
    let end_count = checkpoints
        .iter()
        .filter(|cp| cp.name == "NEGOTIATE_END")
        .count();
    prop_assert_eq!(
        end_count,
        1,
        "{}: expected exactly one NEGOTIATE_END, got {}",
        side_label,
        end_count
    );

    // Find the indices of the anchors
    let start_idx = checkpoints
        .iter()
        .position(|cp| cp.name == "NEGOTIATE_START")
        .unwrap();
    let end_idx = checkpoints
        .iter()
        .position(|cp| cp.name == "NEGOTIATE_END")
        .unwrap();

    // (a) The first checkpoint is NEGOTIATE_START with timestamp_ns == 0
    prop_assert_eq!(
        start_idx,
        0,
        "{}: NEGOTIATE_START must be the first element (index 0), found at index {}",
        side_label,
        start_idx
    );
    prop_assert_eq!(
        checkpoints[start_idx].timestamp_ns,
        0,
        "{}: NEGOTIATE_START should have timestamp_ns == 0, got {}",
        side_label,
        checkpoints[start_idx].timestamp_ns
    );

    // (b) NEGOTIATE_END comes after START
    prop_assert!(
        end_idx > start_idx,
        "{}: NEGOTIATE_END (index {}) must come after NEGOTIATE_START (index {})",
        side_label,
        end_idx,
        start_idx
    );

    // The handshake sequence is checkpoints[start_idx..=end_idx].
    // It must have at least 3 elements: START + message(s) + END.
    let handshake_len = end_idx - start_idx + 1;
    prop_assert!(
        handshake_len >= 3,
        "{}: handshake sequence must have at least 3 elements (START + msg + END), got {}",
        side_label,
        handshake_len
    );

    // (e) All checkpoints strictly between START and END are message checkpoints
    //     (i.e., not anchors)
    for i in (start_idx + 1)..end_idx {
        let cp = &checkpoints[i];
        prop_assert!(
            cp.name != "NEGOTIATE_START" && cp.name != "NEGOTIATE_END",
            "{}: checkpoint at index {} between anchors has unexpected anchor name {:?}",
            side_label,
            i,
            cp.name
        );
    }

    Ok(())
}
