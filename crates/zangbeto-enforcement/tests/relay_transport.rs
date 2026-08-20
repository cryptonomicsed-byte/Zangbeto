//! End-to-end relay transport tests against a loopback mock relay.
//!
//! The unit tests in `src/nostr_relay.rs` cover frame parsing with no socket.
//! These drive the real socket path — connect, NIP-42 handshake, publish,
//! read-back — against a minimal relay on `127.0.0.1`, so protocol sequencing
//! is exercised without depending on an external relay being reachable,
//! admitting the guardian's key, or being up.
//!
//! The mock is strict about what has actually bitten this ecosystem: it refuses
//! writes before auth, and answers `REQ` only for events it genuinely stored.

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpListener;
use tungstenite::Message;
use uuid::Uuid;

use zangbeto_enforcement::action_ladder::{EnforcementAction, LogLevel};
use zangbeto_enforcement::daemon::EnforcementReceipt;
use zangbeto_enforcement::nostr_bridge::{enforcement_engram, GuardianNostrIdentity};
use zangbeto_enforcement::nostr_relay::{RelayClient, RelayError};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    RejectAuth,
    RejectEvent,
    AcceptButDoNotStore,
}

/// Start a mock relay on an ephemeral port. Returns its `ws://` URL.
///
/// No readiness probe: `bind` already puts the socket in the listening state,
/// so a client connect queues in the backlog. Probing with a throwaway
/// connection would consume the mock's single `accept()` and leave the real
/// client unable to connect.
async fn start_mock_relay(mode: Mode) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
            return;
        };

        let mut authenticated = false;
        let mut stored: Vec<Value> = Vec::new();

        // NIP-42: the relay opens with a challenge.
        let _ = ws
            .send(Message::Text(r#"["AUTH","mock-challenge"]"#.into()))
            .await;

        while let Some(Ok(msg)) = ws.next().await {
            let Message::Text(text) = msg else {
                continue;
            };
            let Ok(frame) = serde_json::from_str::<Vec<Value>>(&text) else {
                continue;
            };

            match frame.first().and_then(Value::as_str).unwrap_or_default() {
                "AUTH" => {
                    let id = frame
                        .get(1)
                        .and_then(|e| e.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let reply = if mode == Mode::RejectAuth {
                        format!(r#"["OK","{id}",false,"auth-required: rejected"]"#)
                    } else {
                        authenticated = true;
                        format!(r#"["OK","{id}",true,""]"#)
                    };
                    let _ = ws.send(Message::Text(reply.into())).await;
                }
                "EVENT" => {
                    let event = frame.get(1).cloned().unwrap_or(Value::Null);
                    let id = event
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();

                    // The real relay refuses writes before auth, reporting it as
                    // an OK-false that reads like something unrelated.
                    let reply = if !authenticated {
                        format!(r#"["OK","{id}",false,"auth-required: not authenticated"]"#)
                    } else if mode == Mode::RejectEvent {
                        format!(r#"["OK","{id}",false,"restricted: unknown event kind"]"#)
                    } else {
                        if mode != Mode::AcceptButDoNotStore {
                            stored.push(event);
                        }
                        format!(r#"["OK","{id}",true,""]"#)
                    };
                    let _ = ws.send(Message::Text(reply.into())).await;
                }
                "REQ" => {
                    let sub = frame.get(1).and_then(Value::as_str).unwrap_or_default().to_string();
                    let wanted: Vec<String> = frame
                        .get(2)
                        .and_then(|f| f.get("ids"))
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                        .unwrap_or_default();

                    for ev in &stored {
                        let id = ev.get("id").and_then(Value::as_str).unwrap_or_default();
                        if wanted.iter().any(|w| w == id) {
                            let _ = ws
                                .send(Message::Text(format!(r#"["EVENT","{sub}",{ev}]"#).into()))
                                .await;
                        }
                    }
                    let _ = ws
                        .send(Message::Text(format!(r#"["EOSE","{sub}"]"#).into()))
                        .await;
                }
                _ => {}
            }
        }
    });

    format!("ws://127.0.0.1:{port}")
}

fn identity() -> GuardianNostrIdentity {
    GuardianNostrIdentity::from_guardian_seed(&[7u8; 32]).unwrap()
}

fn a_receipt() -> EnforcementReceipt {
    EnforcementReceipt {
        receipt_id: Uuid::new_v4(),
        anomaly_id: Uuid::new_v4(),
        action_taken: EnforcementAction::Observe {
            log_level: LogLevel::Warn,
            retain_evidence: true,
        },
        execution_timestamp: 1_700_000_000,
        state_before: [1u8; 32],
        state_after: [2u8; 32],
        orisha_signatures: Vec::new(),
        merkle_proof: [3u8; 32],
    }
}

fn an_event(id: &GuardianNostrIdentity) -> nostr::Event {
    enforcement_engram(id, &a_receipt(), id.public_key_hex()).unwrap()
}

#[tokio::test]
async fn the_full_authenticated_publish_path_works() {
    let url = start_mock_relay(Mode::Normal).await;
    let id = identity();

    let mut client = RelayClient::connect_authenticated(&url, &id)
        .await
        .expect("connect and authenticate");
    assert!(client.is_authenticated());

    client.publish(&an_event(&id)).await.expect("accepted");
    client.close().await;
}

#[tokio::test]
async fn a_verified_publish_reads_the_receipt_back() {
    let url = start_mock_relay(Mode::Normal).await;
    let id = identity();

    let mut client = RelayClient::connect_authenticated(&url, &id).await.unwrap();
    client
        .publish_verified(&an_event(&id))
        .await
        .expect("receipt should be retrievable after publish");
    client.close().await;
}

#[tokio::test]
async fn an_accepted_but_unstored_receipt_is_reported_as_not_retrievable() {
    // The failure publish_verified exists for. An enforcement receipt that the
    // relay claims to have accepted but does not serve is exactly the case
    // where trusting the OK would leave an audit trail that is not there.
    let url = start_mock_relay(Mode::AcceptButDoNotStore).await;
    let id = identity();

    let mut client = RelayClient::connect_authenticated(&url, &id).await.unwrap();
    let err = client.publish_verified(&an_event(&id)).await.unwrap_err();
    assert!(
        matches!(err, RelayError::NotRetrievable(_)),
        "expected NotRetrievable, got {err:?}"
    );
}

#[tokio::test]
async fn a_rejected_receipt_is_an_error_never_a_success() {
    let url = start_mock_relay(Mode::RejectEvent).await;
    let id = identity();

    let mut client = RelayClient::connect_authenticated(&url, &id).await.unwrap();
    match client.publish(&an_event(&id)).await.unwrap_err() {
        RelayError::Rejected { message, .. } => {
            assert!(message.contains("unknown event kind"), "message: {message}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn publishing_before_auth_surfaces_the_relays_refusal() {
    // This is the frame that fooled minipae, arriving over a real socket.
    let url = start_mock_relay(Mode::Normal).await;
    let id = identity();

    let mut client = RelayClient::connect(&url).await.unwrap();
    assert!(!client.is_authenticated());

    match client.publish(&an_event(&id)).await.unwrap_err() {
        RelayError::Rejected { message, .. } => {
            assert!(message.contains("auth-required"), "message: {message}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_refused_auth_fails_at_connect_time() {
    let url = start_mock_relay(Mode::RejectAuth).await;
    let err = RelayClient::connect_authenticated(&url, &identity())
        .await
        .unwrap_err();
    assert!(matches!(err, RelayError::AuthFailed(_)), "got {err:?}");
}

#[tokio::test]
async fn connecting_to_a_dead_address_errors_rather_than_hanging() {
    // Port 1 on loopback: nothing listens, connection refused immediately.
    let err = RelayClient::connect_authenticated("ws://127.0.0.1:1", &identity())
        .await
        .unwrap_err();
    assert!(matches!(err, RelayError::Connect { .. }), "got {err:?}");
}
