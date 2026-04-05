//! Error types for VaultGuard
//!
//! All error types are designed to avoid leaking sensitive information.
//! Error messages visible to end users never contain key material,
//! plaintext data, or internal implementation details.

use serde::Serialize;
use std::fmt;

/// Result type alias for VaultGuard operations
pub type VaultResult<T> = Result<T, VaultError>;

/// Error types for vault operations
///
/// Each variant is carefully designed to provide useful debugging info
/// without leaking sensitive data.
#[derive(Debug, Clone, Serialize)]
pub enum VaultError {
    /// Invalid master password (decryption failed)
    InvalidPassword,
    /// Vault file integrity violation (HMAC mismatch or tampering detected)
    IntegrityViolation(String),
    /// Vault is currently locked — unlock required
    VaultLocked,
    /// Vault already exists — cannot create a new one
    VaultAlreadyExists,
    /// Vault does not exist — needs initial setup
    VaultNotFound,
    /// Entry not found by ID
    EntryNotFound(String),
    /// Category not found by ID
    CategoryNotFound(String),
    /// Brute force protection triggered
    BruteForceLockedOut {
        remaining_seconds: u64,
        message: String,
    },
    /// Primary vault is corrupted, but a verified backup is available to restore.
    BackupRestoreAvailable {
        message: String,
    },
    /// Cryptographic operation failed
    Crypto(String),
    /// File I/O error
    Io(String),
    /// Data serialization/deserialization error
    Serialization(String),
    /// Import/export error
    ImportExport(String),
    /// Validation error (bad input)
    Validation(String),
    /// Session token missing or invalid
    Unauthorized,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::InvalidPassword => write!(f, "Invalid master password"),
            VaultError::IntegrityViolation(msg) => write!(f, "Integrity violation: {}", msg),
            VaultError::VaultLocked => write!(f, "Vault is locked"),
            VaultError::VaultAlreadyExists => write!(f, "Vault already exists"),
            VaultError::VaultNotFound => write!(f, "Vault not found"),
            VaultError::EntryNotFound(id) => write!(f, "Entry not found: {}", id),
            VaultError::CategoryNotFound(id) => write!(f, "Category not found: {}", id),
            VaultError::BruteForceLockedOut { message, .. } => write!(f, "{}", message),
            VaultError::BackupRestoreAvailable { message } => write!(f, "{}", message),
            VaultError::Crypto(msg) => write!(f, "Cryptographic error: {}", msg),
            VaultError::Io(msg) => write!(f, "I/O error: {}", msg),
            VaultError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            VaultError::ImportExport(msg) => write!(f, "Import/Export error: {}", msg),
            VaultError::Validation(msg) => write!(f, "Validation error: {}", msg),
            VaultError::Unauthorized => write!(f, "Authorization required"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        VaultError::Serialization(e.to_string())
    }
}
