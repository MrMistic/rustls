//! Per-message handshake timing instrumentation (feature = "timing").
//!
//! Mirrors the s2n-tls checkpoint design (aws/s2n-tls#5903) so handshake
//! timings are directly comparable across implementations.
//!
//! # Clock source
//!
//! Uses [`std::time::Instant`] — a monotonic, non-decreasing clock. On Linux this is
//! typically backed by `CLOCK_MONOTONIC` (not `CLOCK_MONOTONIC_RAW`).
//!
//! **Divergence from s2n-tls**: s2n-tls' `s2n_default_monotonic_clock` uses
//! `CLOCK_MONOTONIC_RAW`, which is not subject to NTP slewing/adjtime.
//! `CLOCK_MONOTONIC` (used by Rust's `Instant`) *is* subject to NTP slewing.
//! For per-message *relative* breakdowns over a sub-second handshake this
//! difference is negligible; absolute cross-implementation latency comparisons
//! should treat it as a caveat.
//!
//! # Epoch model
//!
//! All `timestamp_ns` values are **relative** — elapsed nanoseconds since the
//! per-connection `NEGOTIATE_START` epoch. `NEGOTIATE_START` itself always has
//! `timestamp_ns == 0`. Per-message deltas remain comparable across
//! implementations despite the relative-vs-absolute epoch difference (s2n
//! records absolute monotonic readings; the harness derives deltas).
//!
//! # Resolution
//!
//! Nanoseconds (`u64`).

use alloc::string::String;
use std::time::Instant;

use crate::common_state::Side;
use crate::enums::HandshakeType;
use crate::msgs::message::{Message, MessagePayload};
use crate::sync::Arc;

/// Which side of the connection emitted a checkpoint.
///
/// The integer encoding matches s2n-tls: server = 0, client = 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Server role; encodes to 0.
    Server,
    /// Client role; encodes to 1.
    Client,
}

impl Role {
    /// s2n-parity integer encoding (server = 0, client = 1).
    #[inline]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Server => 0,
            Self::Client => 1,
        }
    }
}

impl From<Side> for Role {
    fn from(side: Side) -> Self {
        match side {
            Side::Server => Self::Server,
            Side::Client => Self::Client,
        }
    }
}

/// A single timing checkpoint, structurally identical to the s2n-tls record.
///
/// Exactly three fields, matching s2n-tls (`name`, `role`, `timestamp_ns`).
#[derive(Clone, Debug)]
pub struct TimingCheckpoint {
    /// Message or anchor name, UPPER_SNAKE_CASE (e.g. `CLIENT_HELLO`,
    /// `NEGOTIATE_START`). Always non-empty.
    pub name: String,
    /// Emitting connection's role.
    pub role: Role,
    /// Elapsed nanoseconds since this connection's NEGOTIATE_START epoch.
    /// The NEGOTIATE_START checkpoint itself has `timestamp_ns == 0`.
    pub timestamp_ns: u64,
}

/// Consumer-supplied observer that receives each emitted checkpoint.
///
/// Invoked synchronously on the handshake-processing thread, once per
/// checkpoint, in emission order.
pub trait TimingSubscriber: Send + Sync {
    /// Receive one checkpoint by shared reference.
    fn on_timing_checkpoint(&self, checkpoint: &TimingCheckpoint);
}

/// A wrapper around `Option<Arc<dyn TimingSubscriber>>` that implements `Clone` and `Debug`.
///
/// This allows `ClientConfig`/`ServerConfig` to continue using `#[derive(Clone, Debug)]`
/// without requiring `TimingSubscriber` implementors to implement `Debug`.
#[derive(Clone)]
pub struct TimingSubscriberSlot(pub Option<Arc<dyn TimingSubscriber>>);

impl core::fmt::Debug for TimingSubscriberSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(_) => f.write_str("<timing subscriber>"),
            None => f.write_str("None"),
        }
    }
}

/// Internal state carrying the subscriber and per-connection epoch.
pub(crate) struct TimingState {
    /// The registered subscriber (the config always had `Some` to create this).
    subscriber: Arc<dyn TimingSubscriber>,
    /// Per-connection monotonic epoch, set when NEGOTIATE_START is emitted.
    pub(crate) epoch: Option<Instant>,
    /// True once NEGOTIATE_START has been emitted (latch).
    pub(crate) started: bool,
    /// True once NEGOTIATE_END has been emitted (guards against double-end).
    pub(crate) ended: bool,
}

impl TimingState {
    /// Create a new `TimingState` from the given subscriber.
    pub(crate) fn new(subscriber: Arc<dyn TimingSubscriber>) -> Self {
        Self {
            subscriber,
            epoch: None,
            started: false,
            ended: false,
        }
    }

    /// Elapsed nanoseconds since the epoch, using saturating arithmetic.
    pub(crate) fn elapsed_ns_now(&self) -> u64 {
        self.epoch
            .map(|epoch| (Instant::now() - epoch).as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Access the subscriber for emitting checkpoints.
    pub(crate) fn subscriber(&self) -> &dyn TimingSubscriber {
        &*self.subscriber
    }
}

/// Map a handshake type and connection side to an s2n-aligned UPPER_SNAKE name.
///
/// The mapping is receiver-relative: when a *client* receives a `Certificate`,
/// it is the server's certificate → `SERVER_CERT`.
///
/// Deterministic: identical (type, side) inputs always yield identical output.
pub(crate) fn message_name(ty: HandshakeType, side: Side) -> &'static str {
    match ty {
        HandshakeType::ClientHello => "CLIENT_HELLO",
        HandshakeType::ServerHello => "SERVER_HELLO",
        HandshakeType::HelloRetryRequest => "HELLO_RETRY_REQUEST",
        HandshakeType::EncryptedExtensions => "ENCRYPTED_EXTENSIONS",
        HandshakeType::Certificate => match side {
            Side::Client => "SERVER_CERT",
            Side::Server => "CLIENT_CERT",
        },
        HandshakeType::CertificateVerify => match side {
            Side::Client => "SERVER_CERT_VERIFY",
            Side::Server => "CLIENT_CERT_VERIFY",
        },
        HandshakeType::Finished => match side {
            Side::Client => "SERVER_FINISHED",
            Side::Server => "CLIENT_FINISHED",
        },
        // Fallback table for all other known HandshakeType variants.
        other => fallback_name(other),
    }
}

/// Deterministic fallback for HandshakeType variants not in the core vocabulary.
fn fallback_name(ty: HandshakeType) -> &'static str {
    match ty {
        HandshakeType::HelloRequest => "HELLO_REQUEST",
        HandshakeType::HelloVerifyRequest => "HELLO_VERIFY_REQUEST",
        HandshakeType::NewSessionTicket => "NEW_SESSION_TICKET",
        HandshakeType::EndOfEarlyData => "END_OF_EARLY_DATA",
        HandshakeType::ServerKeyExchange => "SERVER_KEY_EXCHANGE",
        HandshakeType::CertificateRequest => "CERTIFICATE_REQUEST",
        HandshakeType::ServerHelloDone => "SERVER_HELLO_DONE",
        HandshakeType::ClientKeyExchange => "CLIENT_KEY_EXCHANGE",
        HandshakeType::CertificateURL => "CERTIFICATE_URL",
        HandshakeType::CertificateStatus => "CERTIFICATE_STATUS",
        HandshakeType::KeyUpdate => "KEY_UPDATE",
        HandshakeType::CompressedCertificate => "COMPRESSED_CERTIFICATE",
        HandshakeType::MessageHash => "MESSAGE_HASH",
        HandshakeType::Unknown(_) => "UNKNOWN_HANDSHAKE",
        // The core vocabulary types are handled by message_name directly;
        // this arm should not be reached for them but we need exhaustiveness.
        _ => "UNKNOWN_HANDSHAKE",
    }
}

/// Extract the `HandshakeType` from a parsed handshake message.
///
/// # Panics
///
/// Panics if `msg` is not a `MessagePayload::Handshake`.
pub(crate) fn handshake_type_of(msg: &Message<'_>) -> HandshakeType {
    match &msg.payload {
        MessagePayload::Handshake { parsed, .. } => parsed.0.handshake_type(),
        _ => unreachable!("handshake_type_of called on non-Handshake message"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn message_name_core_vocabulary() {
        // Requirement 5.2
        assert_eq!(message_name(HandshakeType::ClientHello, Side::Client), "CLIENT_HELLO");
        assert_eq!(message_name(HandshakeType::ClientHello, Side::Server), "CLIENT_HELLO");

        // Requirement 5.3
        assert_eq!(message_name(HandshakeType::ServerHello, Side::Client), "SERVER_HELLO");
        assert_eq!(message_name(HandshakeType::ServerHello, Side::Server), "SERVER_HELLO");

        // Requirement 5.4
        assert_eq!(
            message_name(HandshakeType::EncryptedExtensions, Side::Client),
            "ENCRYPTED_EXTENSIONS"
        );
        assert_eq!(
            message_name(HandshakeType::EncryptedExtensions, Side::Server),
            "ENCRYPTED_EXTENSIONS"
        );

        // Requirement 5.5 - Certificate processed by client
        assert_eq!(message_name(HandshakeType::Certificate, Side::Client), "SERVER_CERT");
        // Requirement 5.6 - Certificate processed by server
        assert_eq!(message_name(HandshakeType::Certificate, Side::Server), "CLIENT_CERT");

        // Requirement 5.7 - CertificateVerify processed by client
        assert_eq!(
            message_name(HandshakeType::CertificateVerify, Side::Client),
            "SERVER_CERT_VERIFY"
        );
        // Requirement 5.8 - CertificateVerify processed by server
        assert_eq!(
            message_name(HandshakeType::CertificateVerify, Side::Server),
            "CLIENT_CERT_VERIFY"
        );

        // Requirement 5.9 - Finished processed by client
        assert_eq!(message_name(HandshakeType::Finished, Side::Client), "SERVER_FINISHED");
        // Requirement 5.10 - Finished processed by server
        assert_eq!(message_name(HandshakeType::Finished, Side::Server), "CLIENT_FINISHED");
    }

    #[test]
    fn role_encoding() {
        // Requirement 3.2
        assert_eq!(Role::Server.as_u8(), 0);
        // Requirement 3.3
        assert_eq!(Role::Client.as_u8(), 1);
    }

    #[test]
    fn timing_subscriber_is_send_sync() {
        // Requirement 8.1 - static assertion
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn TimingSubscriber>();
    }

    // Feature: rustls-timing-instrumentation, Property 6: Message-name mapping is total and deterministic

    /// Generate an arbitrary Side (Client or Server).
    fn arb_side() -> impl Strategy<Value = Side> {
        prop_oneof![Just(Side::Client), Just(Side::Server),]
    }

    /// Validates: Requirements 5.1–5.11
    ///
    /// Property 6: Message-name mapping is total and deterministic
    ///
    /// For any HandshakeType (including Unknown(u8) over full u8 range) × Side:
    /// - message_name returns a non-empty string
    /// - The string is UPPER_SNAKE_CASE (only uppercase letters, digits, and underscores)
    /// - Calling it twice yields the same result (deterministic)
    mod property6 {
        use super::*;

        proptest! {
            #[test]
            fn message_name_is_total_and_deterministic(
                raw_type in 0u8..=255u8,
                side in arb_side(),
            ) {
                let ty = HandshakeType::from(raw_type);
                let name = message_name(ty, side);

                // Non-empty
                prop_assert!(!name.is_empty(), "message_name returned empty string for {:?}, {:?}", ty, side);

                // UPPER_SNAKE_CASE: only uppercase letters, digits, and underscores
                prop_assert!(
                    name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                    "message_name returned non-UPPER_SNAKE_CASE string {:?} for {:?}, {:?}",
                    name, ty, side
                );

                // Deterministic: calling twice yields the same result
                let name2 = message_name(ty, side);
                prop_assert_eq!(name, name2, "message_name not deterministic for {:?}, {:?}", ty, side);
            }

            #[test]
            fn core_vocabulary_matches_fixed_table(
                side in arb_side(),
            ) {
                // Core vocabulary types must map to their expected s2n-aligned names
                assert_eq!(message_name(HandshakeType::ClientHello, side), "CLIENT_HELLO");
                assert_eq!(message_name(HandshakeType::ServerHello, side), "SERVER_HELLO");
                assert_eq!(message_name(HandshakeType::HelloRetryRequest, side), "HELLO_RETRY_REQUEST");
                assert_eq!(message_name(HandshakeType::EncryptedExtensions, side), "ENCRYPTED_EXTENSIONS");

                // Role-dependent types
                match side {
                    Side::Client => {
                        assert_eq!(message_name(HandshakeType::Certificate, side), "SERVER_CERT");
                        assert_eq!(message_name(HandshakeType::CertificateVerify, side), "SERVER_CERT_VERIFY");
                        assert_eq!(message_name(HandshakeType::Finished, side), "SERVER_FINISHED");
                    }
                    Side::Server => {
                        assert_eq!(message_name(HandshakeType::Certificate, side), "CLIENT_CERT");
                        assert_eq!(message_name(HandshakeType::CertificateVerify, side), "CLIENT_CERT_VERIFY");
                        assert_eq!(message_name(HandshakeType::Finished, side), "CLIENT_FINISHED");
                    }
                }

                // Unknown variants always produce UNKNOWN_HANDSHAKE
                assert_eq!(message_name(HandshakeType::Unknown(0x07), side), "UNKNOWN_HANDSHAKE");
                assert_eq!(message_name(HandshakeType::Unknown(0xFF), side), "UNKNOWN_HANDSHAKE");
            }
        }
    }
}
