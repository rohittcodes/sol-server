use axum::response::Json as JsonResponse;
use solana_sdk::{signature::{Keypair, Signer}};
use crate::types::*;
use bs58;

pub async fn generate_keypair() -> JsonResponse<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    JsonResponse(ApiResponse::success(KeypairResponse { pubkey, secret }))
}