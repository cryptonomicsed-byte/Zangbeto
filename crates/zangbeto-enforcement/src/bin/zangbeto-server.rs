//! ZÀNGBÉTÒ enforcement HTTP bridge binary.
//!
//! Serves `POST /enforce`, `POST /review`, and `GET /health` so the Ọmọ Kọ́dà
//! runtime can reach the enforcer over the wire (the address it expects in
//! `ZANGBETO_URL`). Port via `ZANGBETO_PORT` (default 8787).

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("ZANGBETO_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);

    let app = zangbeto_enforcement::http::router();
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("🕯 ZÀNGBÉTÒ enforcement HTTP bridge listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
