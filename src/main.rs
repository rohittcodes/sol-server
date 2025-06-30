mod handlers;
mod types;

use axum::{Router, routing::post};
use handlers::*;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("Server running on: {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}