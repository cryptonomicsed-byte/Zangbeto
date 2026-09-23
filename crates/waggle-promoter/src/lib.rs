//! waggle-promoter — Zangbeto verification results climb the evidence ladder.
//!
//! Connection Map v2 §1.9 / §10: Zangbeto's pass/fail is the mechanism that
//! promotes a Waggle signal from `watch-derived` to `zangbeto-verified` —
//! one step below on-chain anchoring. A replay verification (see
//! `replay-engine::verify_trace`) that passes re-deposits the finding at the
//! higher tier; a failure deposits a `warn` instead, because a receipt that
//! does not replay is itself a finding.
//!
//! Promotion is always a NEW deposit: stored history is never rewritten,
//! the journal keeps the whole ladder climb, and read paths weight the
//! highest-tier signal on the resource.
//!
//! Std only (raw HTTP/1.1 over TcpStream, hand-built JSON) so the promoter
//! runs inside any verification sandbox. Fails soft: an unreachable field
//! never fails a verification run.

use std::io::{Read, Write};
use std::net::TcpStream;

/// One verification outcome to promote onto the field.
#[derive(Debug, Clone)]
pub struct Promotion {
    /// Resource URI the original signal lives on.
    pub resource: String,
    /// Receipt / trace id that was replayed.
    pub receipt_id: String,
    /// Did the replay verify?
    pub passed: bool,
    /// Optional robustness score from the receipt's metrics (0..1); when
    /// present, a `bounded` verdict is promoted alongside the gold.
    pub robustness: Option<f64>,
}

impl Promotion {
    /// The deposit bodies this promotion sends, exposed for testing and for
    /// callers that want to journal them elsewhere too.
    pub fn deposits(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.passed {
            out.push(format!(
                concat!(
                    "{{\"agent\":\"zangbeto\",\"resource\":\"{}\",\"kind\":\"gold\",",
                    "\"intensity\":5,\"evidence_tier\":\"zangbeto-verified\",",
                    "\"note\":\"replay verified\",\"meta\":{{\"receipt\":\"{}\"}}}}"
                ),
                esc(&self.resource),
                esc(&self.receipt_id)
            ));
            if let Some(r) = self.robustness {
                let r = r.clamp(0.0, 1.0);
                out.push(format!(
                    concat!(
                        "{{\"agent\":\"zangbeto\",\"resource\":\"{}\",\"kind\":\"bounded\",",
                        "\"intensity\":{:.3},\"evidence_tier\":\"zangbeto-verified\",",
                        "\"note\":\"receipt robustness, replay verified\",",
                        "\"meta\":{{\"receipt\":\"{}\",\"source\":\"zangbeto\"}}}}"
                    ),
                    esc(&self.resource),
                    10.0 * r,
                    esc(&self.receipt_id)
                ));
            }
        } else {
            out.push(format!(
                concat!(
                    "{{\"agent\":\"zangbeto\",\"resource\":\"{}\",\"kind\":\"warn\",",
                    "\"intensity\":6,\"evidence_tier\":\"watch-derived\",",
                    "\"note\":\"receipt failed replay verification\",",
                    "\"meta\":{{\"receipt\":\"{}\"}}}}"
                ),
                esc(&self.resource),
                esc(&self.receipt_id)
            ));
        }
        out
    }

    /// Send the promotion to the field. Returns how many deposits landed.
    pub fn send(&self) -> usize {
        let host = waggle_host();
        self.deposits()
            .iter()
            .filter(|body| post(&host, "/v1/signals", body).is_some())
            .count()
    }
}

fn waggle_host() -> String {
    std::env::var("WAGGLE_URL")
        .unwrap_or_else(|_| "127.0.0.1:7777".into())
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:7777")
        .to_string()
}

fn post(host: &str, path: &str, body: &str) -> Option<String> {
    let mut stream = TcpStream::connect(host).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok()?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let ok = text.lines().next().is_some_and(|l| l.contains("200"));
    ok.then_some(text)
}

fn esc(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            '\n' => "\\n".chars().collect(),
            c => vec![c],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_with_robustness_promotes_gold_and_bounded() {
        let p = Promotion {
            resource: "osovm://bytecode/abc".into(),
            receipt_id: "r-42".into(),
            passed: true,
            robustness: Some(0.83),
        };
        let d = p.deposits();
        assert_eq!(d.len(), 2);
        assert!(d[0].contains("\"kind\":\"gold\""));
        assert!(d[0].contains("zangbeto-verified"));
        assert!(d[1].contains("\"kind\":\"bounded\""));
        assert!(d[1].contains("\"intensity\":8.3"));
    }

    #[test]
    fn failure_becomes_a_warning_not_a_promotion() {
        let p = Promotion {
            resource: "osovm://bytecode/bad".into(),
            receipt_id: "r-13".into(),
            passed: false,
            robustness: Some(0.9), // ignored: no promotion without a pass
        };
        let d = p.deposits();
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("\"kind\":\"warn\""));
        assert!(!d[0].contains("zangbeto-verified\",\"note\":\"replay verified"));
    }

    #[test]
    fn robustness_is_clamped() {
        let p = Promotion {
            resource: "r".into(),
            receipt_id: "x".into(),
            passed: true,
            robustness: Some(7.0),
        };
        assert!(p.deposits()[1].contains("\"intensity\":10"));
    }
}
