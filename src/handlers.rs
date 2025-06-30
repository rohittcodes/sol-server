use axum::{extract::Json, response::{Json as JsonResponse, Response, IntoResponse}, http::StatusCode};
use solana_sdk::{pubkey::Pubkey, signature::{Keypair, Signer}, system_instruction};
use spl_token::instruction as token_instruction;
use std::str::FromStr;
use base64::Engine;
use std::convert::TryFrom;
use crate::types::*;
use bs58;

pub async fn generate_keypair() -> JsonResponse<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    JsonResponse(ApiResponse::success(KeypairResponse { pubkey, secret }))
}

pub async fn create_token(Json(req): Json<CreateTokenRequest>) -> Response {
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid mint authority public key"))).into_response(),
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid mint public key"))).into_response(),
    };
    if req.decimals > 9 {
        return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Decimals must be between 0 and 9"))).into_response();
    }
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(), &mint, &mint_authority, Some(&mint_authority), req.decimals
    ).unwrap();
    let accounts = instruction.accounts.iter().map(AccountMeta::from).collect();
    JsonResponse(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    })).into_response()
}

pub async fn mint_token(Json(req): Json<MintTokenRequest>) -> Response {
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid mint address"))).into_response(),
    };
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid destination address"))).into_response(),
    };
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid authority address"))).into_response(),
    };
    if req.amount == 0 {
        return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Amount must be greater than 0"))).into_response();
    }
    let instruction = token_instruction::mint_to(
        &spl_token::id(), &mint, &destination, &authority, &[], req.amount
    ).unwrap();
    let accounts = instruction.accounts.iter().map(AccountMeta::from).collect();
    JsonResponse(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    })).into_response()
}

pub async fn sign_message(Json(req): Json<SignMessageRequest>) -> Response {
    if req.message.is_empty() || req.secret.is_empty() {
        return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<SignMessageResponse>::error("Missing required fields"))).into_response();
    }
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<SignMessageResponse>::error("Invalid secret key format"))).into_response(),
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<SignMessageResponse>::error("Invalid secret key"))).into_response(),
    };
    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let public_key = keypair.pubkey().to_string();
    JsonResponse(ApiResponse::success(SignMessageResponse {
        signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
        public_key,
        message: req.message,
    })).into_response()
}

pub async fn verify_message(Json(req): Json<VerifyMessageRequest>) -> Response {
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<VerifyMessageResponse>::error("Missing required fields"))).into_response();
    }
    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<VerifyMessageResponse>::error("Invalid public key"))).into_response(),
    };
    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<VerifyMessageResponse>::error("Invalid signature format"))).into_response(),
    };
    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<VerifyMessageResponse>::error("Invalid signature"))).into_response(),
    };
    let message_bytes = req.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);
    JsonResponse(ApiResponse::success(VerifyMessageResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    })).into_response()
}

pub async fn send_sol(Json(req): Json<SendSolRequest>) -> Response {
    let from = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid sender address"))).into_response(),
    };
    let to = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid recipient address"))).into_response(),
    };
    if req.lamports == 0 {
        return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Amount must be greater than 0"))).into_response();
    }
    if from == to {
        return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Sender and recipient addresses must be different"))).into_response();
    }
    let instruction = system_instruction::transfer(&from, &to, req.lamports);
    let accounts = instruction.accounts.iter().map(AccountMeta::from).collect();
    JsonResponse(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    })).into_response()
}

pub async fn send_token(Json(req): Json<SendTokenRequest>) -> Response {
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid destination address"))).into_response(),
    };
    let _mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid mint address"))).into_response(),
    };
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Invalid owner address"))).into_response(),
    };
    if req.amount == 0 {
        return (StatusCode::BAD_REQUEST, JsonResponse(ApiResponse::<InstructionResponse>::error("Amount must be greater than 0"))).into_response();
    }
    let instruction = token_instruction::transfer(
        &spl_token::id(), &owner, &destination, &owner, &[], req.amount
    ).unwrap();
    let accounts = instruction.accounts.iter().map(AccountMeta::from).collect();
    JsonResponse(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    })).into_response()
}