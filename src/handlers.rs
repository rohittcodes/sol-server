use axum::{extract::Json, response::Json as JsonResponse};
use solana_sdk::{pubkey::Pubkey, signature::{Keypair, Signer}};
use spl_token::instruction as token_instruction;
use std::str::FromStr;
use base64::Engine;
use crate::types::*;
use bs58;

pub async fn generate_keypair() -> JsonResponse<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    JsonResponse(ApiResponse::success(KeypairResponse { pubkey, secret }))
}

// ← Add this new function
pub async fn create_token(Json(req): Json<CreateTokenRequest>) -> JsonResponse<ApiResponse<InstructionResponse>> {
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return JsonResponse(ApiResponse::error("Invalid mint authority public key")),
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return JsonResponse(ApiResponse::error("Invalid mint public key")),
    };
    if req.decimals > 9 {
        return JsonResponse(ApiResponse::error("Decimals must be between 0 and 9"));
    }
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(), &mint, &mint_authority, Some(&mint_authority), req.decimals
    ).unwrap();
    let accounts = instruction.accounts.iter().map(AccountMeta::from).collect();
    JsonResponse(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    }))
}