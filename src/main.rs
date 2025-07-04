mod handlers;
mod types;

use axum::{Router, routing::{post, get}, Json, http::StatusCode, response::{IntoResponse, Response}, middleware};
use handlers::*;
use serde_json::json;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(middleware::from_fn(handle_422_errors));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("Server running on: {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handle_422_errors(
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, StatusCode> {
    let response = next.run(req).await;
    
    if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
        let error_response = Json(json!({
            "success": false,
            "error": "Invalid or missing fields"
        }));
        return Ok((StatusCode::BAD_REQUEST, error_response).into_response());
    }
    
    Ok(response)
}

async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "name": "Solana API Server",
        "version": "1.0.0",
        "endpoints": {
            "POST /keypair": "Generate a new Solana keypair",
            "POST /token/create": "Create a new SPL token",
            "POST /token/mint": "Mint tokens to an account",
            "POST /message/sign": "Sign a message with a keypair",
            "POST /message/verify": "Verify a signed message",
            "POST /send/sol": "Create SOL transfer instruction",
            "POST /send/token": "Create token transfer instruction"
        }
    }))
}