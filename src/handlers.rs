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
    let response = ApiResponse::success(KeypairResponse { pubkey, secret });
    println!("[generate_keypair] response: {}", serde_json::to_string(&response).unwrap());
    JsonResponse(response)
}

pub async fn create_token(Json(req): Json<CreateTokenRequest>) -> Response {
    println!("[create_token] request: {}", serde_json::to_string(&req).unwrap());
    if req.mint_authority.trim().is_empty() || req.mint.trim().is_empty() {
        let response = ApiResponse::<InstructionResponse>::error("Missing required fields");
        println!("[create_token] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error("Invalid mint authority public key");
            println!("[create_token] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error("Invalid mint public key");
            println!("[create_token] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(), &mint, &mint_authority, Some(&mint_authority), req.decimals
    ).unwrap();
    let accounts = instruction.accounts.iter().map(AccountMeta::from).collect();
    let response = ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    });
    println!("[create_token] response: {}", serde_json::to_string(&response).unwrap());
    JsonResponse(response).into_response()
}

pub async fn mint_token(Json(req): Json<MintTokenRequest>) -> Response {
    println!("[mint_token] request: {}", serde_json::to_string(&req).unwrap());
    if req.mint.trim().is_empty() || req.destination.trim().is_empty() || req.authority.trim().is_empty() {
        let response = ApiResponse::<InstructionResponse>::error("Missing required fields");
        println!("[mint_token] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error("Invalid mint address");
            println!("[mint_token] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error("Invalid destination address");
            println!("[mint_token] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<InstructionResponse>::error("Invalid authority address");
            println!("[mint_token] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    if req.amount == 0 {
        let response = ApiResponse::<InstructionResponse>::error("Amount must be greater than 0");
        println!("[mint_token] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let instruction = token_instruction::mint_to(
        &spl_token::id(), &mint, &destination, &authority, &[], req.amount
    ).unwrap();
    let accounts = instruction.accounts.iter().map(AccountMeta::from).collect();
    let response = ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    });
    println!("[mint_token] response: {}", serde_json::to_string(&response).unwrap());
    JsonResponse(response).into_response()
}

pub async fn sign_message(Json(req): Json<SignMessageRequest>) -> Response {
    println!("[sign_message] request: {}", serde_json::to_string(&req).unwrap());
    if req.message.trim().is_empty() || req.secret.trim().is_empty() {
        let response = ApiResponse::<SignMessageResponse>::error("Missing required fields");
        println!("[sign_message] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = ApiResponse::<SignMessageResponse>::error("Invalid secret key format");
            println!("[sign_message] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            let response = ApiResponse::<SignMessageResponse>::error("Invalid secret key");
            println!("[sign_message] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let public_key = keypair.pubkey().to_string();
    let response = ApiResponse::success(SignMessageResponse {
        signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
        public_key,
        message: req.message,
    });
    println!("[sign_message] response: {}", serde_json::to_string(&response).unwrap());
    JsonResponse(response).into_response()
}

pub async fn verify_message(Json(req): Json<VerifyMessageRequest>) -> Response {
    println!("[verify_message] request: {}", serde_json::to_string(&req).unwrap());
    if req.message.trim().is_empty() || req.signature.trim().is_empty() || req.pubkey.trim().is_empty() {
        let response = ApiResponse::<VerifyMessageResponse>::error("Missing required fields");
        println!("[verify_message] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<VerifyMessageResponse>::error("Invalid public key");
            println!("[verify_message] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = ApiResponse::<VerifyMessageResponse>::error("Invalid signature format");
            println!("[verify_message] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            let response = ApiResponse::<VerifyMessageResponse>::error("Invalid signature");
            println!("[verify_message] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let message_bytes = req.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);
    let response = ApiResponse::success(VerifyMessageResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    });
    println!("[verify_message] response: {}", serde_json::to_string(&response).unwrap());
    JsonResponse(response).into_response()
}

pub async fn send_sol(Json(req): Json<SendSolRequest>) -> Response {
    println!("[send_sol] request: {}", serde_json::to_string(&req).unwrap());
    if req.from.trim().is_empty() || req.to.trim().is_empty() {
        let response = ApiResponse::<SendSolResponse>::error("Missing required fields");
        println!("[send_sol] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let from = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendSolResponse>::error("Invalid sender address");
            println!("[send_sol] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let to = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendSolResponse>::error("Invalid recipient address");
            println!("[send_sol] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    if req.lamports == 0 {
        let response = ApiResponse::<SendSolResponse>::error("Amount must be greater than 0");
        println!("[send_sol] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    if from == to {
        let response = ApiResponse::<SendSolResponse>::error("Sender and recipient addresses must be different");
        println!("[send_sol] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let instruction = system_instruction::transfer(&from, &to, req.lamports);
    let accounts = instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect();
    let response = ApiResponse::success(SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    });
    println!("[send_sol] response: {}", serde_json::to_string(&response).unwrap());
    JsonResponse(response).into_response()
}

pub async fn send_token(Json(req): Json<SendTokenRequest>) -> Response {
    println!("[send_token] request: {}", serde_json::to_string(&req).unwrap());
    if req.destination.trim().is_empty() || req.mint.trim().is_empty() || req.owner.trim().is_empty() {
        let response = ApiResponse::<SendTokenResponse>::error("Missing required fields");
        println!("[send_token] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendTokenResponse>::error("Invalid destination address");
            println!("[send_token] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let _mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendTokenResponse>::error("Invalid mint address");
            println!("[send_token] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<SendTokenResponse>::error("Invalid owner address");
            println!("[send_token] response: {}", serde_json::to_string(&response).unwrap());
            return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
        }
    };
    if req.amount == 0 {
        let response = ApiResponse::<SendTokenResponse>::error("Amount must be greater than 0");
        println!("[send_token] response: {}", serde_json::to_string(&response).unwrap());
        return (StatusCode::BAD_REQUEST, JsonResponse(response)).into_response();
    }
    let instruction = token_instruction::transfer(
        &spl_token::id(), &owner, &destination, &owner, &[], req.amount
    ).unwrap();
    let accounts = instruction.accounts.iter().map(|acc| SendTokenAccount {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();
    let response = ApiResponse::success(SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    });
    println!("[send_token] response: {}", serde_json::to_string(&response).unwrap());
    JsonResponse(response).into_response()
}

 