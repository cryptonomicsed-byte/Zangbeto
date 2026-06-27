//! ZÀNGBÉTÒ enforcement bridge binary.
//!
//! Listens on `ZANGBETO_BIND` (default `0.0.0.0:8787`) and serves the HTTP
//! enforcement API so remote Ọmọ Kọ́dà runtimes can request enforcement
//! decisions for an agent.

#[tokio::main]
async fn main() {
    let addr = std::env::var("ZANGBETO_BIND").unwrap_or_else(|_| "0.0.0.0:8787".to_string());
    eprintln!("🕯 ZÀNGBÉTÒ enforcement bridge listening on {addr}");
    if let Err(e) = zangbeto_enforcement::server::serve(&addr).await {
        eprintln!("zangbeto server error: {e}");
        std::process::exit(1);
    }
}
