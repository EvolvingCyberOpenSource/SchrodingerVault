#[derive(Debug)]
pub enum ErrorCode {
    WrongPassword,
    CorruptedEntry,
    MissingDeviceKey,
    TamperedVault,
    IoError,
}

impl ErrorCode {
    pub fn message(&self) -> &'static str {
        match self {
            ErrorCode::WrongPassword => "That password didn’t work.",
            ErrorCode::CorruptedEntry => "Couldn’t decrypt this entry.",
            ErrorCode::MissingDeviceKey => "Device key not found. Please import your backup.",
            ErrorCode::TamperedVault => "Vault has been modified outside the app. Unlock blocked.",
            ErrorCode::IoError => "File access error.",
        }
    }
}

#[derive(Debug)]
pub struct VaultError {
    pub code: ErrorCode,
    pub message: String,
}

impl VaultError {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            message: code.message().to_string(),
            code,
        }
    }
}
