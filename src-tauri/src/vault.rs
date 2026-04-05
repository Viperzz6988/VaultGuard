//! Vault file operations for VaultGuard
//!
//! Binary vault file format:
//! [4 bytes: magic "VALT"]
//! [1 byte: version (0x01)]
//! [32 bytes: Argon2id salt]
//! [60 bytes: encrypted DEK (12 nonce + 32 ciphertext + 16 GCM tag)]
//! [variable: encrypted vault data (12 nonce + ciphertext + 16 GCM tag)]
//! [32 bytes: HMAC-SHA256 over everything before HMAC]

use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto::{self, HMAC_SIZE, KEY_SIZE, SALT_SIZE};
use crate::error::{VaultError, VaultResult};
use crate::models::VaultData;
use crate::security;

/// Magic bytes identifying a VaultGuard vault file
const VAULT_MAGIC: &[u8; 4] = b"VALT";
/// Current vault format version
const VAULT_VERSION: u8 = 0x01;
/// Size of the header (magic + version + salt)
const HEADER_SIZE: usize = 4 + 1 + SALT_SIZE; // 37 bytes
/// Size of the encrypted DEK block (nonce + ciphertext + GCM tag)
const ENCRYPTED_DEK_SIZE: usize = 12 + KEY_SIZE + 16; // 60 bytes
const VAULT_CORRUPTION_MESSAGE: &str =
    "Vault file has been tampered with or corrupted. Access denied.";
const BACKUP_RESTORE_MESSAGE: &str =
    "Primary vault file appears corrupted. Restore from last good backup?";

pub struct LoadedVault {
    pub data: VaultData,
    pub kek: Zeroizing<[u8; KEY_SIZE]>,
    pub dek: Zeroizing<[u8; KEY_SIZE]>,
    pub salt: [u8; SALT_SIZE],
    pub normalized_on_load: bool,
}

/// Get the default vault file path
pub fn vault_path() -> VaultResult<PathBuf> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| VaultError::Io("Cannot determine local data directory".into()))?;
    let vault_dir = data_dir.join("vaultguard");
    Ok(vault_dir.join("vault.enc"))
}

/// Check if a vault file exists at the given path
pub fn vault_exists(path: &Path) -> bool {
    path.exists() && path.is_file()
}

pub fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("enc.bak")
}

fn temp_vault_path(path: &Path) -> PathBuf {
    path.with_extension("enc.tmp")
}

fn temp_backup_path(path: &Path) -> PathBuf {
    path.with_extension("enc.bak.tmp")
}

fn ensure_vault_parent(path: &Path) -> VaultResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        security::set_file_permissions(parent, 0o700);
    }
    Ok(())
}

pub fn set_runtime_read_only(path: &Path, read_only: bool) -> VaultResult<()> {
    if !path.exists() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(if read_only { 0o444 } else { 0o600 });
        fs::set_permissions(path, permissions)?;
    }

    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(read_only);
        fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

fn write_bytes_atomically(path: &Path, bytes: &[u8], make_read_only: bool) -> VaultResult<()> {
    ensure_vault_parent(path)?;
    let _ = set_runtime_read_only(path, false);

    let tmp_path = temp_vault_path(path);
    let write_result = (|| -> VaultResult<()> {
        fs::write(&tmp_path, bytes)?;
        fs::rename(&tmp_path, path)?;
        security::set_file_permissions(path, 0o600);
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = set_runtime_read_only(path, true);
        return Err(error);
    }

    if make_read_only {
        if let Err(error) = set_runtime_read_only(path, true) {
            let _ = set_runtime_read_only(path, true);
            return Err(error);
        }
    }

    Ok(())
}

fn write_backup_atomically(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    let backup_path = backup_path(path);
    ensure_vault_parent(&backup_path)?;

    let tmp_path = temp_backup_path(path);
    fs::write(&tmp_path, bytes)?;
    fs::rename(&tmp_path, &backup_path)?;
    security::set_file_permissions(&backup_path, 0o600);
    Ok(())
}

fn corruption_error() -> VaultError {
    VaultError::IntegrityViolation(VAULT_CORRUPTION_MESSAGE.into())
}

fn load_vault_file(password: &str, path: &Path, make_read_only: bool) -> VaultResult<LoadedVault> {
    if !vault_exists(path) {
        return Err(VaultError::VaultNotFound);
    }

    if !security::check_file_permissions(path) {
        log::warn!("Vault file permissions are broader than owner-only access");
    }

    let file_data = fs::read(path)?;
    let min_size = HEADER_SIZE + ENCRYPTED_DEK_SIZE + 12 + 16 + HMAC_SIZE;
    if file_data.len() < min_size {
        return Err(corruption_error());
    }

    if &file_data[0..4] != VAULT_MAGIC {
        return Err(corruption_error());
    }

    if file_data[4] != VAULT_VERSION {
        return Err(corruption_error());
    }

    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&file_data[5..5 + SALT_SIZE]);
    let kek = crypto::derive_kek(password.as_bytes(), &salt)?;

    let hmac_start = file_data.len() - HMAC_SIZE;
    let mut stored_hmac = [0u8; HMAC_SIZE];
    stored_hmac.copy_from_slice(&file_data[hmac_start..]);

    let dek_start = HEADER_SIZE;
    let dek_end = dek_start + ENCRYPTED_DEK_SIZE;
    let encrypted_dek = &file_data[dek_start..dek_end];
    let encrypted_data = &file_data[dek_end..hmac_start];
    let data_without_hmac = &file_data[..hmac_start];

    if !crypto::verify_hmac(data_without_hmac, &stored_hmac, &kek)? {
        match crypto::decrypt_dek(encrypted_dek, &kek) {
            Ok(dek) => {
                let _ = crypto::decrypt_data(encrypted_data, &dek);
                return Err(corruption_error());
            }
            Err(VaultError::InvalidPassword) => {
                return Err(VaultError::InvalidPassword);
            }
            Err(_) => {
                return Err(corruption_error());
            }
        }
    }

    let dek = crypto::decrypt_dek(encrypted_dek, &kek)?;
    let vault_json = crypto::decrypt_data(encrypted_data, &dek)?;
    let mut vault_data: VaultData = serde_json::from_slice(&vault_json)
        .map_err(|e| VaultError::Serialization(format!("Failed to parse vault data: {}", e)))?;
    let normalized_on_load = crate::models::normalize_vault_data(&mut vault_data);

    if make_read_only {
        set_runtime_read_only(path, true)?;
    }

    Ok(LoadedVault {
        data: vault_data,
        kek,
        dek,
        salt,
        normalized_on_load,
    })
}

/// Create a new vault with the given master password
///
/// This generates a fresh salt and DEK, encrypts everything,
/// and writes the vault file with proper permissions.
pub fn create_vault(password: &str, path: &Path) -> VaultResult<()> {
    if vault_exists(path) {
        return Err(VaultError::VaultAlreadyExists);
    }

    ensure_vault_parent(path)?;

    // Generate cryptographic materials
    let salt = crypto::generate_salt();
    let kek = crypto::derive_kek(password.as_bytes(), &salt)?;
    let dek = crypto::generate_dek();

    // Create empty vault
    let vault_data = VaultData::new_empty();

    // Serialize vault data
    let vault_json = serde_json::to_vec(&vault_data)?;

    // Encrypt DEK with KEK
    let encrypted_dek = crypto::encrypt_dek(&dek, &kek)?;

    // Encrypt vault data with DEK
    let encrypted_data = crypto::encrypt_data(&vault_json, &dek)?;

    // Build the vault file contents (everything except HMAC)
    let mut file_data = Vec::new();
    file_data.extend_from_slice(VAULT_MAGIC);
    file_data.push(VAULT_VERSION);
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&encrypted_dek);
    file_data.extend_from_slice(&encrypted_data);

    // Compute HMAC over everything
    let hmac = crypto::compute_hmac(&file_data, &kek)?;
    file_data.extend_from_slice(&hmac);

    write_bytes_atomically(path, &file_data, true)?;
    write_backup_atomically(path, &file_data)?;
    Ok(())
}

/// Load and decrypt a vault with the given master password
///
/// Performs HMAC verification before attempting decryption.
/// Returns the decrypted vault data along with the KEK, DEK, and salt
/// for subsequent save operations.
pub fn load_vault(
    password: &str,
    path: &Path,
) -> VaultResult<LoadedVault> {
    let primary_result = load_vault_file(password, path, true);
    let backup_restorable = || {
        let backup = backup_path(path);
        vault_exists(&backup) && load_vault_file(password, &backup, false).is_ok()
    };

    match primary_result {
        Ok(loaded) => Ok(loaded),
        Err(VaultError::InvalidPassword) => {
            if backup_restorable() {
                Err(VaultError::BackupRestoreAvailable {
                    message: BACKUP_RESTORE_MESSAGE.into(),
                })
            } else {
                Err(VaultError::InvalidPassword)
            }
        }
        Err(VaultError::IntegrityViolation(_)) => {
            if backup_restorable() {
                Err(VaultError::BackupRestoreAvailable {
                    message: BACKUP_RESTORE_MESSAGE.into(),
                })
            } else {
                Err(corruption_error())
            }
        }
        Err(error) => Err(error),
    }
}

/// Save vault data to disk
///
/// Re-encrypts all data with the existing DEK and recomputes the HMAC.
/// Uses atomic write (temp file + rename) to prevent corruption.
pub fn save_vault(
    data: &VaultData,
    dek: &[u8; KEY_SIZE],
    kek: &[u8; KEY_SIZE],
    salt: &[u8; SALT_SIZE],
    path: &Path,
) -> VaultResult<()> {
    ensure_vault_parent(path)?;

    // Serialize vault data
    let vault_json = serde_json::to_vec(data)?;

    // Re-encrypt DEK (with fresh nonce)
    let encrypted_dek = crypto::encrypt_dek(dek, kek)?;

    // Encrypt vault data (with fresh nonce)
    let encrypted_data = crypto::encrypt_data(&vault_json, dek)?;

    // Build file contents
    let mut file_data = Vec::new();
    file_data.extend_from_slice(VAULT_MAGIC);
    file_data.push(VAULT_VERSION);
    file_data.extend_from_slice(salt);
    file_data.extend_from_slice(&encrypted_dek);
    file_data.extend_from_slice(&encrypted_data);

    // Compute HMAC
    let hmac = crypto::compute_hmac(&file_data, kek)?;
    file_data.extend_from_slice(&hmac);

    write_bytes_atomically(path, &file_data, true)?;
    write_backup_atomically(path, &file_data)?;
    Ok(())
}

/// Export vault as encrypted backup
///
/// Creates a copy of the vault file with a timestamp in the filename.
pub fn export_backup(path: &Path, export_dir: &Path) -> VaultResult<PathBuf> {
    if !vault_exists(path) {
        return Err(VaultError::VaultNotFound);
    }

    fs::create_dir_all(export_dir)?;

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_name = format!("vaultguard_backup_{}.enc", timestamp);
    let backup_path = export_dir.join(backup_name);

    fs::copy(path, &backup_path)?;
    security::set_file_permissions(&backup_path, 0o600);

    Ok(backup_path)
}

/// Change the master password
///
/// Re-derives the KEK with a new password, re-encrypts the DEK, and saves.
pub fn change_master_password(
    data: &VaultData,
    dek: &[u8; KEY_SIZE],
    new_password: &str,
    path: &Path,
) -> VaultResult<(Zeroizing<[u8; KEY_SIZE]>, [u8; SALT_SIZE])> {
    // Generate new salt
    let new_salt = crypto::generate_salt();

    // Derive new KEK
    let new_kek = crypto::derive_kek(new_password.as_bytes(), &new_salt)?;

    // Save with new KEK (DEK stays the same — only re-encrypted)
    save_vault(data, dek, &new_kek, &new_salt, path)?;

    Ok((new_kek, new_salt))
}

pub fn restore_last_good_backup(password: &str, path: &Path) -> VaultResult<()> {
    let backup = backup_path(path);
    if !vault_exists(&backup) {
        return Err(VaultError::IntegrityViolation(
            "No verified vault backup is available for recovery.".into(),
        ));
    }

    let _ = load_vault_file(password, &backup, false)?;
    let backup_bytes = fs::read(&backup)?;
    write_bytes_atomically(path, &backup_bytes, true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault_path(name: &str) -> PathBuf {
        let unique = uuid::Uuid::new_v4().to_string();
        std::env::temp_dir().join(format!("vaultguard-{}-{}.enc", name, unique))
    }

    #[test]
    fn create_and_load_vault_roundtrip() {
        let path = test_vault_path("roundtrip");
        create_vault("CorrectHorseBatteryStaple!42", &path)
            .expect("test should create vault on disk");

        let loaded = load_vault("CorrectHorseBatteryStaple!42", &path)
            .expect("test should load created vault");
        assert!(loaded.data.entries.is_empty());
        assert_eq!(loaded.data.categories.len(), 3);
        assert_eq!(loaded.data.categories[0].id, crate::models::BUILTIN_LOGIN_CATEGORY_ID);
        assert_eq!(
            loaded.data.categories[1].id,
            crate::models::BUILTIN_API_KEYS_CATEGORY_ID
        );
        assert_eq!(loaded.data.categories[2].id, crate::models::BUILTIN_OTHER_CATEGORY_ID);
        assert!(!loaded.normalized_on_load);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn tampered_vault_is_rejected() {
        let path = test_vault_path("tamper");
        create_vault("CorrectHorseBatteryStaple!42", &path)
            .expect("test should create vault before tampering");
        let _ = fs::remove_file(backup_path(&path));
        set_runtime_read_only(&path, false).expect("test should make vault writable");

        let mut bytes = fs::read(&path).expect("test should read vault bytes");
        let last_data_byte = bytes.len() - HMAC_SIZE - 1;
        bytes[last_data_byte] ^= 0x01;
        fs::write(&path, bytes).expect("test should write tampered vault");

        let result = load_vault("CorrectHorseBatteryStaple!42", &path);
        assert!(matches!(result, Err(VaultError::IntegrityViolation(_))));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn save_writes_backup_and_restore_recovers_primary() {
        let path = test_vault_path("backup-restore");
        let password = "CorrectHorseBatteryStaple!42";
        create_vault(password, &path).expect("test should create vault before backup check");
        assert!(vault_exists(&backup_path(&path)));

        set_runtime_read_only(&path, false).expect("test should make vault writable");
        let mut bytes = fs::read(&path).expect("test should read vault before tampering");
        let last_data_byte = bytes.len() - HMAC_SIZE - 1;
        bytes[last_data_byte] ^= 0x01;
        fs::write(&path, bytes).expect("test should write tampered vault");

        assert!(matches!(
            load_vault(password, &path),
            Err(VaultError::BackupRestoreAvailable { .. })
        ));

        restore_last_good_backup(password, &path).expect("test should restore backup");
        assert!(load_vault(password, &path).is_ok());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn changing_master_password_rotates_unlock_material() {
        let path = test_vault_path("change-password");
        let original_password = "CorrectHorseBatteryStaple!42";
        let new_password = "NewHorseBatteryStaple!84";

        create_vault(original_password, &path).expect("test should create vault before rotation");
        let loaded = load_vault(original_password, &path)
            .expect("test should load vault before rotation");
        change_master_password(&loaded.data, &loaded.dek, new_password, &path)
            .expect("test should rotate vault master password");

        assert!(matches!(
            load_vault(original_password, &path),
            Err(VaultError::InvalidPassword)
        ));
        assert!(load_vault(new_password, &path).is_ok());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn wrong_master_password_is_rejected() {
        let path = test_vault_path("wrong-password");
        let password = "CorrectHorseBatteryStaple!42";

        create_vault(password, &path).expect("test should create vault before wrong-password check");

        assert!(matches!(
            load_vault("DefinitelyWrongPassword!9", &path),
            Err(VaultError::InvalidPassword)
        ));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }
}
