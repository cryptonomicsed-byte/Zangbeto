//! Relay transport for enforcement receipts.
//!
//! [`crate::nostr_bridge`] builds and signs; this connects, authenticates,
//! publishes, and reads back.
//!
//! # Async, because this is a daemon
//!
//! The enforcement daemon runs on tokio (it serves axum). A blocking socket
//! call inside that runtime stalls every other task on the worker thread, so
//! transport here is `async` even though IfáScript's equivalent is sync — that
//! crate has no runtime and does not need one.
//!
//! # Why parsing is separated from the socket
//!
//! minipae shipped a real bug in exactly this spot: `publish()` misread
//! NIP-01's `OK` frame and reported the relay's
//! `auth-required: not authenticated` **rejection** as `ok: True`, so a publish
//! that stored nothing looked successful. That is a parsing bug, and parsing is
//! testable with no relay present. [`parse_frame`] is pure and directly tested,
//! including against the exact frame that fooled minipae.
//!
//! # Why an OK is not believed
//!
//! An `OK` is the relay asserting it accepted the event, not proof the event is
//! retrievable. [`RelayClient::publish_verified`] issues a separate `REQ` for
//! the id and requires the relay to serve it back before reporting success.
//! For an audit record whose whole purpose is to be independently checkable,
//! "probably stored" is not good enough.

use futures_util::{SinkExt, StreamExt};
use nostr::Event;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tungstenite::Message;

use crate::nostr_bridge::{relay_auth, BridgeError, GuardianNostrIdentity};

/// Errors from talking to a relay.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("connecting to {url} failed: {source}")]
    Connect {
        url: String,
        #[source]
        source: Box<tungstenite::Error>,
    },
    #[error("websocket transport error: {0}")]
    Transport(String),
    #[error("relay sent a frame that is not valid JSON: {0}")]
    MalformedFrame(String),
    /// The relay explicitly refused the event, with its stated reason.
    #[error("relay rejected event {event_id}: {message}")]
    Rejected { event_id: String, message: String },
    #[error("NIP-42 authentication failed: {0}")]
    AuthFailed(String),
    /// Accepted by the relay but not served back.
    #[error("event {0} was accepted but could not be read back")]
    NotRetrievable(String),
    #[error(transparent)]
    Bridge(#[from] BridgeError),
}

/// A NIP-01 message from a relay, in the forms this client acts on.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayMessage {
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    Auth {
        challenge: String,
    },
    Event {
        sub_id: String,
        event: Box<Value>,
    },
    EndOfStoredEvents {
        sub_id: String,
    },
    Closed {
        sub_id: String,
        message: String,
    },
    Notice {
        message: String,
    },
    /// A well-formed JSON array with no handling here — never an error, so a
    /// relay extension cannot break an otherwise-fine publish.
    Unhandled(String),
}

fn s(arr: &[Value], i: usize) -> String {
    arr.get(i).and_then(Value::as_str).unwrap_or_default().to_string()
}

/// Parse one relay frame.
pub fn parse_frame(text: &str) -> Result<RelayMessage, RelayError> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| RelayError::MalformedFrame(e.to_string()))?;
    let arr = value
        .as_array()
        .ok_or_else(|| RelayError::MalformedFrame("frame is not a JSON array".into()))?;

    Ok(match arr.first().and_then(Value::as_str).unwrap_or_default() {
        // The acceptance flag is index 2. Index 1 is the event id, always a
        // non-empty (therefore truthy) string -- reading it as the flag is
        // precisely how minipae reported rejections as successes. Anything at
        // index 2 that is not a real boolean counts as NOT accepted: a relay
        // that has not clearly said yes has not said yes.
        "OK" => RelayMessage::Ok {
            event_id: s(arr, 1),
            accepted: arr.get(2).and_then(Value::as_bool).unwrap_or(false),
            message: s(arr, 3),
        },
        "AUTH" => RelayMessage::Auth {
            challenge: s(arr, 1),
        },
        "EVENT" => RelayMessage::Event {
            sub_id: s(arr, 1),
            event: Box::new(arr.get(2).cloned().unwrap_or(Value::Null)),
        },
        "EOSE" => RelayMessage::EndOfStoredEvents { sub_id: s(arr, 1) },
        "CLOSED" => RelayMessage::Closed {
            sub_id: s(arr, 1),
            message: s(arr, 2),
        },
        "NOTICE" => RelayMessage::Notice { message: s(arr, 1) },
        _ => RelayMessage::Unhandled(text.to_string()),
    })
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// An open, optionally authenticated connection to one relay.
pub struct RelayClient {
    socket: Socket,
    url: String,
    authenticated: bool,
}

impl std::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayClient")
            .field("url", &self.url)
            .field("authenticated", &self.authenticated)
            .finish()
    }
}

impl RelayClient {
    /// Open a connection without authenticating.
    pub async fn connect(url: &str) -> Result<Self, RelayError> {
        let (socket, _) = connect_async(url).await.map_err(|e| RelayError::Connect {
            url: url.to_string(),
            source: Box::new(e),
        })?;
        Ok(Self {
            socket,
            url: url.to_string(),
            authenticated: false,
        })
    }

    /// Open a connection and complete NIP-42 authentication.
    ///
    /// The Buzz relay refuses writes from unauthenticated connections and
    /// reports that at publish time as a rejection that reads like an unrelated
    /// failure. Authenticating up front turns it into one clear error here.
    pub async fn connect_authenticated(
        url: &str,
        identity: &GuardianNostrIdentity,
    ) -> Result<Self, RelayError> {
        let mut c = Self::connect(url).await?;
        c.authenticate(identity).await?;
        Ok(c)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Wait for the relay's `AUTH` challenge, answer with a signed `kind:22242`,
    /// and require an accepting `OK`.
    pub async fn authenticate(
        &mut self,
        identity: &GuardianNostrIdentity,
    ) -> Result<(), RelayError> {
        let challenge = loop {
            match self.read().await? {
                RelayMessage::Auth { challenge } => break challenge,
                // A relay may greet with a NOTICE first.
                RelayMessage::Notice { .. } | RelayMessage::Unhandled(_) => continue,
                other => {
                    return Err(RelayError::AuthFailed(format!(
                        "expected an AUTH challenge, got {other:?}"
                    )))
                }
            }
        };

        let auth_event = relay_auth(identity, &challenge, &self.url)?;
        let payload = serde_json::to_string(&auth_event)
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        self.send(&format!("[\"AUTH\",{payload}]")).await?;

        loop {
            match self.read().await? {
                RelayMessage::Ok {
                    accepted, message, ..
                } => {
                    if !accepted {
                        return Err(RelayError::AuthFailed(message));
                    }
                    self.authenticated = true;
                    return Ok(());
                }
                RelayMessage::Notice { .. } | RelayMessage::Unhandled(_) => continue,
                other => {
                    return Err(RelayError::AuthFailed(format!(
                        "expected OK for the auth event, got {other:?}"
                    )))
                }
            }
        }
    }

    /// Publish a signed event and require an accepting `OK`.
    ///
    /// A rejection — including `auth-required` and
    /// `restricted: unknown event kind` — is an error, never a success.
    pub async fn publish(&mut self, event: &Event) -> Result<String, RelayError> {
        let payload =
            serde_json::to_string(event).map_err(|e| RelayError::Transport(e.to_string()))?;
        self.send(&format!("[\"EVENT\",{payload}]")).await?;

        let want = event.id().to_hex();
        loop {
            match self.read().await? {
                RelayMessage::Ok {
                    event_id,
                    accepted,
                    message,
                } => {
                    // The relay may be answering about a different event.
                    if event_id != want {
                        continue;
                    }
                    if !accepted {
                        return Err(RelayError::Rejected { event_id, message });
                    }
                    return Ok(message);
                }
                RelayMessage::Closed { message, .. } => {
                    return Err(RelayError::Rejected {
                        event_id: want,
                        message,
                    })
                }
                _ => continue,
            }
        }
    }

    /// Publish, then independently read the event back before reporting success.
    pub async fn publish_verified(&mut self, event: &Event) -> Result<(), RelayError> {
        self.publish(event).await?;
        let id = event.id().to_hex();
        if !self.has_event(&id).await? {
            return Err(RelayError::NotRetrievable(id));
        }
        Ok(())
    }

    /// Ask the relay whether it serves an event by id.
    pub async fn has_event(&mut self, id_hex: &str) -> Result<bool, RelayError> {
        let sub = "zb-verify";
        self.send(&format!(
            "[\"REQ\",\"{sub}\",{{\"ids\":[\"{id_hex}\"],\"limit\":1}}]"
        ))
        .await?;

        let mut found = false;
        loop {
            match self.read().await? {
                RelayMessage::Event { sub_id, event } if sub_id == sub => {
                    if event.get("id").and_then(Value::as_str) == Some(id_hex) {
                        found = true;
                    }
                }
                RelayMessage::EndOfStoredEvents { sub_id } if sub_id == sub => break,
                RelayMessage::Closed { sub_id, message } if sub_id == sub => {
                    return Err(RelayError::Transport(message))
                }
                _ => continue,
            }
        }

        let _ = self.send(&format!("[\"CLOSE\",\"{sub}\"]")).await;
        Ok(found)
    }

    async fn send(&mut self, text: &str) -> Result<(), RelayError> {
        self.socket
            .send(Message::Text(text.into()))
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))
    }

    async fn read(&mut self) -> Result<RelayMessage, RelayError> {
        loop {
            let Some(msg) = self.socket.next().await else {
                return Err(RelayError::Transport("relay closed the connection".into()));
            };
            match msg.map_err(|e| RelayError::Transport(e.to_string()))? {
                Message::Text(t) => return parse_frame(&t),
                Message::Close(_) => {
                    return Err(RelayError::Transport("relay closed the connection".into()))
                }
                _ => continue,
            }
        }
    }

    /// Close the connection politely.
    pub async fn close(mut self) {
        let _ = self.socket.close(None).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_accepting_ok_is_read_as_accepted() {
        assert_eq!(
            parse_frame(r#"["OK","abc",true,""]"#).unwrap(),
            RelayMessage::Ok {
                event_id: "abc".into(),
                accepted: true,
                message: String::new()
            }
        );
    }

    #[test]
    fn the_exact_rejection_frame_that_fooled_minipae_is_a_rejection() {
        // minipae reported this as ok: True, because index 1 is always a
        // truthy string. An enforcement receipt silently not stored is the
        // worst possible version of this bug.
        let RelayMessage::Ok {
            accepted, message, ..
        } = parse_frame(r#"["OK","abc",false,"auth-required: not authenticated"]"#).unwrap()
        else {
            panic!("expected OK");
        };
        assert!(!accepted);
        assert_eq!(message, "auth-required: not authenticated");
    }

    #[test]
    fn the_unknown_kind_rejection_is_a_rejection() {
        let RelayMessage::Ok { accepted, .. } =
            parse_frame(r#"["OK","abc",false,"restricted: unknown event kind"]"#).unwrap()
        else {
            panic!("expected OK");
        };
        assert!(!accepted);
    }

    #[test]
    fn a_non_boolean_acceptance_flag_counts_as_rejection() {
        for f in [
            r#"["OK","abc","true",""]"#,
            r#"["OK","abc",1,""]"#,
            r#"["OK","abc",null,""]"#,
            r#"["OK","abc"]"#,
        ] {
            let RelayMessage::Ok { accepted, .. } = parse_frame(f).unwrap() else {
                panic!("expected OK for {f}");
            };
            assert!(!accepted, "frame {f} must not read as accepted");
        }
    }

    #[test]
    fn auth_eose_closed_and_notice_parse() {
        assert_eq!(
            parse_frame(r#"["AUTH","chal"]"#).unwrap(),
            RelayMessage::Auth { challenge: "chal".into() }
        );
        assert_eq!(
            parse_frame(r#"["EOSE","s1"]"#).unwrap(),
            RelayMessage::EndOfStoredEvents { sub_id: "s1".into() }
        );
        assert_eq!(
            parse_frame(r#"["CLOSED","s1","restricted"]"#).unwrap(),
            RelayMessage::Closed {
                sub_id: "s1".into(),
                message: "restricted".into()
            }
        );
        assert_eq!(
            parse_frame(r#"["NOTICE","hi"]"#).unwrap(),
            RelayMessage::Notice { message: "hi".into() }
        );
    }

    #[test]
    fn an_unrecognised_verb_is_not_an_error() {
        assert!(matches!(
            parse_frame(r#"["SOMETHING_NEW","x"]"#).unwrap(),
            RelayMessage::Unhandled(_)
        ));
    }

    #[test]
    fn malformed_json_errors_rather_than_silently_succeeding() {
        assert!(matches!(
            parse_frame("not json"),
            Err(RelayError::MalformedFrame(_))
        ));
        assert!(matches!(
            parse_frame(r#"{"not":"an array"}"#),
            Err(RelayError::MalformedFrame(_))
        ));
    }
}
