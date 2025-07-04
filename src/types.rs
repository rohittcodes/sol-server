use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self { success: true, data: Some(data), error: None }
    }
    pub fn error(msg: &str) -> Self {
        Self { success: false, data: None, error: Some(msg.to_string()) }
    }
}

#[derive(Serialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Deserialize, Serialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

#[derive(Deserialize, Serialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

#[derive(Deserialize, Serialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}

#[derive(Serialize)]
pub struct SignMessageResponse {
    pub signature: String,
    #[serde(rename = "public_key")]
    pub public_key: String,
    pub message: String,
}

#[derive(Deserialize, Serialize)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Serialize)]
pub struct VerifyMessageResponse {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

#[derive(Deserialize, Serialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}
 
#[derive(Deserialize, Serialize)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

#[derive(Serialize)]
pub struct SendTokenResponse {
    #[serde(rename = "program_id")]
    pub program_id: String,
    pub accounts: Vec<SendTokenAccount>,
    #[serde(rename = "instruction_data")]
    pub instruction_data: String,
}

#[derive(Serialize)]
pub struct SendTokenAccount {
    pub pubkey: String,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
}

#[derive(Serialize)]
pub struct InstructionResponse {
    #[serde(rename = "program_id")]
    pub program_id: String,
    pub accounts: Vec<AccountMeta>,
    #[serde(rename = "instruction_data")]
    pub instruction_data: String,
}

#[derive(Serialize)]
pub struct SendSolResponse {
    #[serde(rename = "program_id")]
    pub program_id: String,
    pub accounts: Vec<String>,
    #[serde(rename = "instruction_data")]
    pub instruction_data: String,
}

#[derive(Serialize)]
pub struct AccountMeta {
    pub pubkey: String,
    #[serde(rename = "is_signer")]
    pub is_signer: bool,
    #[serde(rename = "is_writable")]
    pub is_writable: bool,
}

impl From<&solana_sdk::instruction::AccountMeta> for AccountMeta {
    fn from(acc: &solana_sdk::instruction::AccountMeta) -> Self {
        Self {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        }
    }
}