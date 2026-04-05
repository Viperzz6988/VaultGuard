//! Tauri IPC command handlers for VaultGuard.
//!
//! This is the only API surface between the frontend and backend.
//! All sensitive operations (crypto, file I/O, clipboard) happen in Rust.
//! The frontend only receives serialized results.

use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::State;
use tauri_plugin_dialog::{DialogExt, FilePath};
use tauri_plugin_opener::OpenerExt;
use url::Url;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::crypto::{self, PasswordGenOptions, StrengthResult, KEY_SIZE, SALT_SIZE};
use crate::error::{VaultError, VaultResult};
use crate::models::*;
use crate::security::{self, BruteForceProtection};
use crate::vault;

/// Application state managed by Tauri.
///
/// Wrapped in `Mutex` for thread-safe access from IPC commands.
/// KEK and DEK are `Option` and become `None` whenever the vault is locked.
pub struct AppState {
    /// Key Encryption Key — derived from master password, None when locked.
    pub kek: Option<Zeroizing<[u8; KEY_SIZE]>>,
    /// Data Encryption Key — decrypted from vault file, None when locked.
    pub dek: Option<Zeroizing<[u8; KEY_SIZE]>>,
    /// Argon2id salt.
    pub salt: Option<[u8; SALT_SIZE]>,
    /// Decrypted vault data — None when locked.
    pub vault_data: Option<VaultData>,
    /// Opaque frontend session token — None when locked.
    pub session_token: Option<Zeroizing<String>>,
    /// Path to the vault file.
    pub vault_path: std::path::PathBuf,
    /// Brute-force protection state.
    pub brute_force: BruteForceProtection,
    /// Last modification timestamp observed after a successful load/save by this app.
    pub last_known_vault_mtime: Option<DateTime<Utc>>,
    /// Startup file-integrity status evaluated before the frontend initializes.
    pub integrity_status: security::StartupIntegrityStatus,
}

impl AppState {
    pub fn new(vault_path: std::path::PathBuf) -> Self {
        let brute_force = BruteForceProtection::load(security::brute_force_state_path(&vault_path));
        let integrity_status = security::startup_integrity_status(&vault_path);

        AppState {
            kek: None,
            dek: None,
            salt: None,
            vault_data: None,
            session_token: None,
            vault_path,
            brute_force,
            last_known_vault_mtime: None,
            integrity_status,
        }
    }

    fn ensure_integrity_ready(&self) -> VaultResult<()> {
        if self.integrity_status.blocked {
            Err(VaultError::IntegrityViolation(
                self.integrity_status
                    .message
                    .clone()
                    .unwrap_or_else(|| "VaultGuard file protection blocked startup".to_string()),
            ))
        } else {
            Ok(())
        }
    }

    fn ensure_unlocked(&self) -> VaultResult<()> {
        self.ensure_integrity_ready()?;
        if self.vault_data.is_none() {
            Err(VaultError::VaultLocked)
        } else {
            Ok(())
        }
    }

    fn ensure_authorized(&self, session_token: &str) -> VaultResult<()> {
        self.ensure_integrity_ready()?;
        let expected = self.session_token.as_ref().ok_or(VaultError::Unauthorized)?;
        if crypto::constant_time_eq(expected.as_bytes(), session_token.as_bytes()) {
            self.ensure_unlocked()
        } else {
            Err(VaultError::Unauthorized)
        }
    }

    fn lock_key_material(&self) {
        if let Some(kek) = self.kek.as_ref() {
            let _ = security::lock_memory(kek.as_ptr(), KEY_SIZE);
        }
        if let Some(dek) = self.dek.as_ref() {
            let _ = security::lock_memory(dek.as_ptr(), KEY_SIZE);
        }
    }

    fn unlock_key_material(&self) {
        if let Some(kek) = self.kek.as_ref() {
            security::unlock_memory(kek.as_ptr(), KEY_SIZE);
        }
        if let Some(dek) = self.dek.as_ref() {
            security::unlock_memory(dek.as_ptr(), KEY_SIZE);
        }
    }

    fn refresh_vault_tracking(&mut self) {
        self.last_known_vault_mtime = security::file_modified_at(&self.vault_path);
    }

    fn refresh_integrity_status(&mut self) {
        self.integrity_status = security::startup_integrity_status(&self.vault_path);
    }

    fn set_unlocked_state(
        &mut self,
        vault_data: VaultData,
        kek: Zeroizing<[u8; KEY_SIZE]>,
        dek: Zeroizing<[u8; KEY_SIZE]>,
        salt: [u8; SALT_SIZE],
    ) {
        self.unlock_key_material();
        self.kek = Some(kek);
        self.dek = Some(dek);
        self.salt = Some(salt);
        self.vault_data = Some(vault_data);
        self.lock_key_material();
        self.refresh_vault_tracking();
    }

    fn issue_session_token(&mut self) -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token = hex_encode(&bytes);
        self.session_token = Some(Zeroizing::new(token.clone()));
        token
    }

    /// Lock the vault and wipe all sensitive data from memory.
    fn lock(&mut self) {
        self.unlock_key_material();
        self.kek = None;
        self.dek = None;
        if let Some(mut salt) = self.salt.take() {
            salt.zeroize();
        }
        self.vault_data = None;
        self.session_token = None;
        self.last_known_vault_mtime = None;
    }

    fn save(&mut self) -> VaultResult<()> {
        let data = self.vault_data.as_ref().ok_or(VaultError::VaultLocked)?;
        let dek = self.dek.as_ref().ok_or(VaultError::VaultLocked)?;
        let kek = self.kek.as_ref().ok_or(VaultError::VaultLocked)?;
        let salt = self.salt.as_ref().ok_or(VaultError::VaultLocked)?;
        vault::save_vault(data, dek, kek, salt, &self.vault_path)?;
        security::refresh_integrity_manifest(&self.vault_path)?;
        self.refresh_vault_tracking();
        Ok(())
    }

    fn vault_file_status(&self) -> VaultFileStatus {
        let current_mtime = security::file_modified_at(&self.vault_path);
        let modified_externally = match (self.last_known_vault_mtime, current_mtime) {
            (Some(expected), Some(actual)) => expected != actual,
            _ => false,
        };

        VaultFileStatus {
            monitored_path: self.vault_path.to_string_lossy().to_string(),
            exists: vault::vault_exists(&self.vault_path),
            permissions_secure: security::check_file_permissions(&self.vault_path),
            modified_externally,
            modified_at: current_mtime,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VaultFileStatus {
    pub monitored_path: String,
    pub exists: bool,
    pub permissions_secure: bool,
    pub modified_externally: bool,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct BitwardenExportFolder {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct BitwardenExportLoginUri {
    uri: String,
}

#[derive(Debug, Serialize)]
struct BitwardenExportLogin {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    uris: Vec<BitwardenExportLoginUri>,
}

#[derive(Debug, Serialize)]
struct BitwardenExportItem {
    object: &'static str,
    r#type: u8,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(rename = "folderId", skip_serializing_if = "Option::is_none")]
    folder_id: Option<String>,
    favorite: bool,
    login: BitwardenExportLogin,
}

#[derive(Debug, Serialize)]
struct BitwardenExport {
    encrypted: bool,
    folders: Vec<BitwardenExportFolder>,
    items: Vec<BitwardenExportItem>,
}

#[derive(Debug, Serialize)]
pub struct UnlockResponse {
    pub brute_force_status: crate::security::BruteForceStatus,
    pub session_token: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReorderPosition {
    Before,
    After,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialogFilterInput {
    pub name: String,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialogOpenOptions {
    pub multiple: Option<bool>,
    pub filters: Option<Vec<DialogFilterInput>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialogSaveOptions {
    pub filters: Option<Vec<DialogFilterInput>>,
    pub default_path: Option<String>,
}

#[derive(Debug, Clone)]
struct ImportedEntry {
    title: String,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    favorite: bool,
    category_name: Option<String>,
}

#[tauri::command]
pub fn dialog_open_file(
    app: tauri::AppHandle,
    options: DialogOpenOptions,
) -> Result<Option<String>, VaultError> {
    if options.multiple.unwrap_or(false) {
        return Err(VaultError::Validation(
            "Selecting multiple files is not supported".into(),
        ));
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let mut builder = app.dialog().file();
    for filter in options.filters.unwrap_or_default() {
        let extensions = filter
            .extensions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        builder = builder.add_filter(&filter.name, &extensions);
    }

    builder.pick_file(move |file_path| {
        let resolved = file_path.and_then(dialog_file_path_to_string);
        let _ = tx.send(resolved);
    });

    rx.recv()
        .map_err(|_| VaultError::Io("Could not read the selected file path".into()))
}

#[tauri::command]
pub fn dialog_save_file(
    app: tauri::AppHandle,
    options: DialogSaveOptions,
) -> Result<Option<String>, VaultError> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut builder = app.dialog().file();
    for filter in options.filters.unwrap_or_default() {
        let extensions = filter
            .extensions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        builder = builder.add_filter(&filter.name, &extensions);
    }

    if let Some(default_path) = options.default_path {
        let path = PathBuf::from(default_path);
        if let Some(parent) = path.parent() {
            builder = builder.set_directory(parent);
        }
        if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
            builder = builder.set_file_name(file_name);
        }
    }

    builder.save_file(move |file_path| {
        let resolved = file_path.and_then(dialog_file_path_to_string);
        let _ = tx.send(resolved);
    });

    rx.recv()
        .map_err(|_| VaultError::Io("Could not read the selected save path".into()))
}

// === Vault lifecycle commands ===

#[tauri::command]
pub fn check_vault_exists(state: State<'_, Mutex<AppState>>) -> Result<bool, VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_integrity_ready()?;
    Ok(vault::vault_exists(&state.vault_path))
}

#[tauri::command]
pub fn check_vault_unlocked(state: State<'_, Mutex<AppState>>) -> Result<bool, VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_integrity_ready()?;
    Ok(state.vault_data.is_some())
}

#[tauri::command]
pub fn get_startup_integrity_status(
    state: State<'_, Mutex<AppState>>,
) -> Result<security::StartupIntegrityStatus, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.refresh_integrity_status();
    Ok(state.integrity_status.clone())
}

#[tauri::command]
pub fn create_vault(
    password: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<UnlockResponse, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_integrity_ready()?;

    let password = Zeroizing::new(password);
    crypto::validate_master_password(password.as_str()).map_err(VaultError::Validation)?;

    vault::create_vault(password.as_str(), &state.vault_path)?;
    let loaded = vault::load_vault(password.as_str(), &state.vault_path)?;
    let normalized_on_load = loaded.normalized_on_load;
    state.brute_force.record_success()?;
    state.set_unlocked_state(loaded.data, loaded.kek, loaded.dek, loaded.salt);
    if normalized_on_load {
        state.save()?;
    }

    Ok(UnlockResponse {
        brute_force_status: state.brute_force.get_status(),
        session_token: state.issue_session_token(),
    })
}

#[tauri::command]
pub fn unlock_vault(
    password: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<UnlockResponse, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_integrity_ready()?;

    state.brute_force.refresh()?;

    if let Some(wait) = state.brute_force.must_wait() {
        return Err(VaultError::BruteForceLockedOut {
            remaining_seconds: wait.as_secs(),
            message: if state.brute_force.is_locked_out() {
                format!(
                    "Too many failed attempts. Vault is locked for {}.",
                    lockout_tier_label(state.brute_force.lockout_tier)
                )
            } else {
                format!("Please wait {} seconds before trying again.", wait.as_secs())
            },
        });
    }

    let password = Zeroizing::new(password);
    match vault::load_vault(password.as_str(), &state.vault_path) {
        Ok(loaded) => {
            let normalized_on_load = loaded.normalized_on_load;
            state.brute_force.record_success()?;
            state.set_unlocked_state(loaded.data, loaded.kek, loaded.dek, loaded.salt);
            if normalized_on_load {
                state.save()?;
            }
            Ok(UnlockResponse {
                brute_force_status: state.brute_force.get_status(),
                session_token: state.issue_session_token(),
            })
        }
        Err(VaultError::InvalidPassword) => {
            state.brute_force.record_failure()?;
            let status = state.brute_force.get_status();
            Err(VaultError::BruteForceLockedOut {
                remaining_seconds: status.lockout_remaining_secs.max(status.delay_secs),
                message: if status.is_locked_out {
                    format!(
                        "Too many failed attempts. Vault is locked for {}.",
                        lockout_tier_label(status.lockout_tier)
                    )
                } else {
                    format!(
                        "Invalid password. {} attempts remaining before lockout.",
                        status.remaining_attempts
                    )
                },
            })
        }
        Err(err) => Err(err),
    }
}

#[tauri::command]
pub fn lock_vault(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    crate::clipboard::clear_clipboard(&app).map_err(VaultError::Io)?;
    state.lock();
    Ok(())
}

#[tauri::command]
pub fn get_brute_force_status(
    state: State<'_, Mutex<AppState>>,
) -> Result<crate::security::BruteForceStatus, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_integrity_ready()?;
    state.brute_force.refresh()?;
    Ok(state.brute_force.get_status())
}

#[tauri::command]
pub fn get_vault_file_status(
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<VaultFileStatus, VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;
    Ok(state.vault_file_status())
}

// === Entry CRUD commands ===

#[tauri::command]
pub fn get_entries(
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<EntrySummary>, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let mut needs_save = false;
    if let Some(data) = state.vault_data.as_mut() {
        let before = data.trash.len();
        data.trash.retain(|t| !t.is_expired());
        needs_save = before != data.trash.len();
    }

    let mut entries = state
        .vault_data
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .entries
        .iter()
        .map(EntrySummary::from)
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        left.category_id
            .cmp(&right.category_id)
            .then_with(|| left.sort_order.cmp(&right.sort_order))
            .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
    });

    if needs_save {
        state.save()?;
    }

    Ok(entries)
}

#[tauri::command]
pub fn get_entry(
    id: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Entry, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    let entry = data
        .entries
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or_else(|| VaultError::EntryNotFound(id.clone()))?;

    entry.accessed_at = Utc::now();
    let result = entry.clone();
    state.save()?;
    Ok(result)
}

#[tauri::command]
pub fn create_entry(
    input: EntryInput,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Entry, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let input = sanitize_entry_input(input)?;
    let mut entry = Entry::new(input.title);
    entry.username = input.username;
    entry.password = input.password;
    entry.url = input.url;
    entry.notes = input.notes;
    entry.category_id = input.category_id;
    entry.tags = input.tags;
    entry.custom_fields = input.custom_fields;
    entry.favorite = input.favorite;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    entry.category_id = normalize_existing_category_id(entry.category_id.take(), &data.categories)
        .or_else(|| Some(BUILTIN_LOGIN_CATEGORY_ID.to_string()));
    entry.sort_order = next_entry_sort_order(&data.entries, entry.category_id.as_deref());
    data.entries.push(entry.clone());
    state.save()?;
    Ok(entry)
}

#[tauri::command]
pub fn update_entry(
    id: String,
    input: EntryInput,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Entry, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let input = sanitize_entry_input(input)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    let entry_index = data
        .entries
        .iter()
        .position(|entry| entry.id == id)
        .ok_or_else(|| VaultError::EntryNotFound(id.clone()))?;
    let new_category_id = normalize_existing_category_id(input.category_id, &data.categories)
        .or_else(|| Some(BUILTIN_LOGIN_CATEGORY_ID.to_string()));
    let category_changed = data.entries[entry_index].category_id != new_category_id;
    let new_sort_order = if category_changed {
        next_entry_sort_order_excluding(&data.entries, new_category_id.as_deref(), &id)
    } else {
        data.entries[entry_index].sort_order
    };

    {
        let entry = &mut data.entries[entry_index];
        let previous_password = entry.password.clone();
        if previous_password.as_deref() != input.password.as_deref() {
            if let Some(old_password) = previous_password.as_deref() {
                entry.push_password_history(old_password);
            }
        }

        entry.title = input.title;
        entry.username = input.username;
        entry.password = input.password;
        entry.url = input.url;
        entry.notes = input.notes;
        entry.category_id = new_category_id;
        entry.tags = input.tags;
        entry.custom_fields = input.custom_fields;
        entry.favorite = input.favorite;
        entry.modified_at = Utc::now();
        entry.sort_order = new_sort_order;
    }

    if category_changed {
        compact_entry_sort_orders(&mut data.entries);
    }

    let result = data.entries[entry_index].clone();
    state.save()?;
    Ok(result)
}

#[tauri::command]
pub fn delete_entry(
    id: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    let position = data
        .entries
        .iter()
        .position(|entry| entry.id == id)
        .ok_or_else(|| VaultError::EntryNotFound(id.clone()))?;

    let entry = data.entries.remove(position);
    data.trash.push(TrashEntry {
        entry,
        deleted_at: Utc::now(),
    });

    state.save()?;
    Ok(())
}

#[tauri::command]
pub fn restore_entry(
    id: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    let position = data
        .trash
        .iter()
        .position(|item| item.entry.id == id)
        .ok_or_else(|| VaultError::EntryNotFound(id.clone()))?;

    let trash_entry = data.trash.remove(position);
    data.entries.push(trash_entry.entry);
    state.save()?;
    Ok(())
}

#[tauri::command]
pub fn permanent_delete(
    id: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    data.trash.retain(|item| item.entry.id != id);
    state.save()?;
    Ok(())
}

#[tauri::command]
pub fn get_trash(
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<TrashEntry>, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let mut needs_save = false;
    if let Some(data) = state.vault_data.as_mut() {
        let before = data.trash.len();
        data.trash.retain(|item| !item.is_expired());
        needs_save = before != data.trash.len();
    }

    let mut trash = state
        .vault_data
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .trash
        .clone();
    trash.sort_by(|left, right| right.deleted_at.cmp(&left.deleted_at));

    if needs_save {
        state.save()?;
    }

    Ok(trash)
}

// === Category commands ===

#[tauri::command]
pub fn get_categories(
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<Category>, VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let mut categories = state
        .vault_data
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .categories
        .clone();
    categories.sort_by_key(|category| category.sort_order);
    Ok(categories)
}

#[tauri::command]
pub fn create_category(
    input: CategoryInput,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Category, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let input = sanitize_category_input(input)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    let order = data.categories.len() as u32;
    let category = Category {
        id: uuid::Uuid::new_v4().to_string(),
        name: input.name,
        emoji: input.emoji,
        color: input.color,
        sort_order: order,
        built_in: false,
    };

    data.categories.push(category.clone());
    state.save()?;
    Ok(category)
}

#[tauri::command]
pub fn update_category(
    id: String,
    input: CategoryInput,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Category, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let input = sanitize_category_input(input)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    let category = data
        .categories
        .iter_mut()
        .find(|category| category.id == id)
        .ok_or_else(|| VaultError::CategoryNotFound(id.clone()))?;

    category.name = input.name;
    category.emoji = input.emoji;
    category.color = input.color;

    let result = category.clone();
    state.save()?;
    Ok(result)
}

#[tauri::command]
pub fn reorder_categories(
    ordered_ids: Vec<String>,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<Category>, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    if ordered_ids.len() != data.categories.len() {
        return Err(VaultError::Validation("Category order payload is incomplete".into()));
    }

    let unique_ids = ordered_ids.iter().collect::<HashSet<_>>();
    if unique_ids.len() != ordered_ids.len() {
        return Err(VaultError::Validation(
            "Category order payload contains duplicate category ids".into(),
        ));
    }

    let mut order_map = HashMap::new();
    for (index, id) in ordered_ids.iter().enumerate() {
        order_map.insert(id.as_str(), index as u32);
    }

    for category in &mut data.categories {
        let new_order = order_map
            .get(category.id.as_str())
            .ok_or_else(|| VaultError::CategoryNotFound(category.id.clone()))?;
        category.sort_order = *new_order;
    }

    normalize_category_order(&mut data.categories);
    let mut categories = data.categories.clone();
    categories.sort_by_key(|category| category.sort_order);
    state.save()?;
    Ok(categories)
}

#[tauri::command]
pub fn reorder_entries(
    entry_id: String,
    new_sort_order: u32,
    new_category_id: Option<String>,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    place_entry_in_category(data, &entry_id, new_category_id, new_sort_order as usize)?;
    state.save()?;
    Ok(())
}

#[tauri::command]
pub fn move_entry_to_category(
    entry_id: String,
    category_id: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    place_entry_in_category(data, &entry_id, Some(category_id), usize::MAX)?;
    state.save()?;
    Ok(())
}

#[tauri::command]
pub fn reorder_entry(
    entry_id: String,
    target_entry_id: String,
    position: ReorderPosition,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
    if entry_id == target_entry_id {
        return Ok(());
    }

    let target_entry = data
        .entries
        .iter()
        .find(|entry| entry.id == target_entry_id)
        .ok_or_else(|| VaultError::EntryNotFound(target_entry_id.clone()))?;
    let target_category_id = target_entry.category_id.clone();
    let ordered_ids =
        sorted_entry_ids_for_category(&data.entries, target_category_id.as_deref(), Some(&entry_id));
    let target_index = ordered_ids
        .iter()
        .position(|id| id == &target_entry_id)
        .ok_or_else(|| VaultError::EntryNotFound(target_entry_id.clone()))?;
    let insert_index = match position {
        ReorderPosition::Before => target_index,
        ReorderPosition::After => target_index.saturating_add(1),
    };

    place_entry_in_category(data, &entry_id, target_category_id, insert_index)?;

    state.save()?;
    Ok(())
}

#[tauri::command]
pub fn delete_category(
    id: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;

    delete_category_from_data(data, &id)?;
    state.save()?;
    Ok(())
}

// === Password generator commands ===

#[tauri::command]
pub fn generate_password(options: PasswordGenOptions) -> Result<String, VaultError> {
    Ok(crypto::generate_password(&options))
}

#[tauri::command]
pub fn generate_passphrase(word_count: usize, separator: String) -> Result<String, VaultError> {
    Ok(crypto::generate_passphrase(word_count, &separator))
}

#[tauri::command]
pub fn check_password_strength(password: String) -> Result<StrengthResult, VaultError> {
    Ok(crypto::check_password_strength(&password))
}

// === Clipboard commands ===

#[tauri::command]
pub fn copy_to_clipboard(
    app: tauri::AppHandle,
    text: String,
    entry_id: Option<String>,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    if let Some(entry_id) = entry_id {
        let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;
        if let Some(entry) = data.entries.iter_mut().find(|entry| entry.id == entry_id) {
            entry.accessed_at = Utc::now();
            state.save()?;
        }
    }

    crate::clipboard::copy_to_clipboard(&app, &text).map_err(VaultError::Io)?;
    Ok(())
}

#[tauri::command]
pub fn schedule_clipboard_clear(
    app: tauri::AppHandle,
    timeout_secs: u64,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    if !is_valid_clipboard_timeout(timeout_secs as u32) {
        return Err(VaultError::Validation(
            "Invalid clipboard auto-clear timeout".into(),
        ));
    }

    crate::clipboard::schedule_clipboard_clear(&app, timeout_secs).map_err(VaultError::Io)?;
    Ok(())
}

#[tauri::command]
pub fn clear_clipboard(app: tauri::AppHandle) -> Result<(), VaultError> {
    crate::clipboard::clear_clipboard(&app).map_err(VaultError::Io)?;
    Ok(())
}

#[tauri::command]
pub fn quit_app(app: tauri::AppHandle) -> Result<(), VaultError> {
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub fn open_url(
    app: tauri::AppHandle,
    url: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    {
        let state = state
            .lock()
            .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
        state.ensure_authorized(&session_token)?;
    }

    let Some(url) = sanitize_optional_url(Some(url))? else {
        return Err(VaultError::Validation("URL is required".into()));
    };

    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| VaultError::Io("Could not open the requested URL".into()))
}

// === Settings commands ===

#[tauri::command]
pub fn get_settings(
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<VaultSettings, VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;
    Ok(state
        .vault_data
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .settings
        .clone())
}

#[tauri::command]
pub fn update_settings(
    input: SettingsInput,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<VaultSettings, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;

    if let Some(auto_lock) = input.auto_lock_minutes {
        if !is_valid_auto_lock(auto_lock) {
            return Err(VaultError::Validation("Invalid auto-lock timeout".into()));
        }
        data.settings.auto_lock_minutes = auto_lock;
    }

    if let Some(clipboard_mode) = input.clipboard_mode {
        data.settings.clipboard_mode = clipboard_mode;
    }

    if let Some(clipboard_timeout) = input.clipboard_timeout_secs {
        if !is_valid_clipboard_timeout(clipboard_timeout) {
            return Err(VaultError::Validation("Invalid clipboard timeout".into()));
        }
        data.settings.clipboard_timeout_secs = clipboard_timeout;
    }

    if let Some(clipboard_remember_choice) = input.clipboard_remember_choice {
        data.settings.clipboard_remember_choice = clipboard_remember_choice;
    }

    if let Some(language) = input.language {
        data.settings.language = sanitize_language(language)?;
    }

    let result = data.settings.clone();
    state.save()?;
    Ok(result)
}

#[tauri::command]
pub fn configure_file_protection(
    enabled: bool,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<security::StartupIntegrityStatus, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;
    let status = security::configure_file_protection(&state.vault_path, enabled)?;
    state.integrity_status = status.clone();
    Ok(status)
}

// === Master password change ===

#[tauri::command]
pub fn change_master_password(
    current_password: String,
    new_password: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);

    let _ = vault::load_vault(current_password.as_str(), &state.vault_path)?;

    crypto::validate_master_password(new_password.as_str()).map_err(VaultError::Validation)?;

    let data = state.vault_data.as_ref().ok_or(VaultError::VaultLocked)?;
    let dek = state.dek.as_ref().ok_or(VaultError::VaultLocked)?;
    let (new_kek, new_salt) =
        vault::change_master_password(data, dek, new_password.as_str(), &state.vault_path)?;

    state.unlock_key_material();
    state.kek = Some(new_kek);
    state.salt = Some(new_salt);
    state.lock_key_material();
    state.refresh_vault_tracking();

    Ok(())
}

// === Import/Export commands ===

#[tauri::command]
pub fn import_vault_data(
    file_path: String,
    format: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<usize, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let content = load_import_file(Path::new(&file_path))?;
    let entries = match format.as_str() {
        "bitwarden" => parse_bitwarden_json(&content)?,
        "keepass" => parse_keepass_xml(&content)?,
        "1password" => parse_1password_csv(&content)?,
        "lastpass" => parse_lastpass_csv(&content)?,
        "dashlane" => parse_dashlane_csv(&content)?,
        "generic" => parse_generic_csv(&content)?,
        _ => return Err(VaultError::Validation("Unsupported import format".into())),
    };

    let imported_count = entries.len();
    append_entries_to_vault(&mut state, entries)?;
    Ok(imported_count)
}

#[tauri::command]
pub fn export_vault_data(
    file_path: String,
    format: String,
    master_password: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let master_password = Zeroizing::new(master_password);
    verify_master_password(&state, master_password.as_str())?;

    let data = state.vault_data.as_ref().ok_or(VaultError::VaultLocked)?;
    let export_bytes = match format.as_str() {
        "encrypted" => export_encrypted_backup(&state.vault_path)?,
        "keepass" => build_keepass_xml(data).into_bytes(),
        "bitwarden" => build_bitwarden_export_json(data)?.into_bytes(),
        _ => return Err(VaultError::Validation("Unsupported export format".into())),
    };

    std::fs::write(&file_path, export_bytes)
        .map_err(|_| VaultError::Io("Could not write the export file".into()))?;
    Ok(())
}

#[tauri::command]
pub fn export_vault_json(
    password: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<String, VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let password = Zeroizing::new(password);
    verify_master_password(&state, password.as_str())?;
    let data = state.vault_data.as_ref().ok_or(VaultError::VaultLocked)?;
    build_bitwarden_export_json(data)
}

#[tauri::command]
pub fn export_keepass_xml(
    password: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<String, VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let password = Zeroizing::new(password);
    verify_master_password(&state, password.as_str())?;
    let data = state.vault_data.as_ref().ok_or(VaultError::VaultLocked)?;
    Ok(build_keepass_xml(data))
}

#[tauri::command]
pub fn export_backup(
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<String, VaultError> {
    let state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;

    let export_dir = dirs::download_dir()
        .or_else(dirs::home_dir)
        .ok_or_else(|| VaultError::Io("Cannot find export directory".into()))?;

    let backup_path = vault::export_backup(&state.vault_path, &export_dir)?;
    Ok(backup_path.to_string_lossy().to_string())
}

#[tauri::command]
pub fn restore_last_good_backup(
    password: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_integrity_ready()?;

    state.lock();
    let password = Zeroizing::new(password);
    vault::restore_last_good_backup(password.as_str(), &state.vault_path)?;
    security::refresh_integrity_manifest(&state.vault_path)?;
    state.refresh_vault_tracking();
    Ok(())
}

#[tauri::command]
pub fn import_bitwarden_json(
    password: String,
    json_content: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<u32, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;
    let password = Zeroizing::new(password);
    verify_master_password(&state, password.as_str())?;

    let entries = parse_bitwarden_json(&json_content)?;
    let count = entries.len() as u32;
    append_entries_to_vault(&mut state, entries)?;
    Ok(count)
}

#[tauri::command]
pub fn import_csv(
    password: String,
    csv_content: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<u32, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;
    let password = Zeroizing::new(password);
    verify_master_password(&state, password.as_str())?;

    let entries = parse_generic_csv(&csv_content)?;
    let count = entries.len() as u32;
    append_entries_to_vault(&mut state, entries)?;
    Ok(count)
}

#[tauri::command]
pub fn import_keepass_xml(
    password: String,
    xml_content: String,
    session_token: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<u32, VaultError> {
    let mut state = state
        .lock()
        .map_err(|_| VaultError::Crypto("State lock poisoned".into()))?;
    state.ensure_authorized(&session_token)?;
    let password = Zeroizing::new(password);
    verify_master_password(&state, password.as_str())?;

    let entries = parse_keepass_xml(&xml_content)?;
    let count = entries.len() as u32;
    append_entries_to_vault(&mut state, entries)?;
    Ok(count)
}

fn verify_master_password(state: &AppState, password: &str) -> VaultResult<()> {
    let _ = vault::load_vault(password, &state.vault_path)?;
    Ok(())
}

fn build_bitwarden_export_json(data: &VaultData) -> VaultResult<String> {
    let folders = data
        .categories
        .iter()
        .map(|category| BitwardenExportFolder {
            id: category.id.clone(),
            name: category.name.clone(),
        })
        .collect::<Vec<_>>();

    let items = data
        .entries
        .iter()
        .map(|entry| BitwardenExportItem {
            object: "item",
            r#type: 1,
            name: entry.title.clone(),
            notes: entry.notes.clone(),
            folder_id: entry.category_id.clone(),
            favorite: entry.favorite,
            login: BitwardenExportLogin {
                username: entry.username.clone(),
                password: entry.password.clone(),
                uris: entry
                    .url
                    .as_ref()
                    .map(|url| vec![BitwardenExportLoginUri { uri: url.clone() }])
                    .unwrap_or_default(),
            },
        })
        .collect::<Vec<_>>();

    let export = BitwardenExport {
        encrypted: false,
        folders,
        items,
    };

    serde_json::to_string_pretty(&export)
        .map_err(|_| VaultError::Serialization("Failed to serialize the Bitwarden export".into()))
}

fn export_encrypted_backup(vault_path: &Path) -> VaultResult<Vec<u8>> {
    std::fs::read(vault_path).map_err(|_| VaultError::Io("Could not read the vault file".into()))
}

fn load_import_file(path: &Path) -> VaultResult<String> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| VaultError::Io("Could not read the selected import file".into()))?;
    if metadata.len() > MAX_IMPORT_FILE_BYTES {
        return Err(VaultError::ImportExport(
            "Import files larger than 10 MB are not supported".into(),
        ));
    }

    std::fs::read_to_string(path)
        .map_err(|_| VaultError::Io("Could not read the selected import file".into()))
}

fn append_entries_to_vault(state: &mut AppState, imported_entries: Vec<ImportedEntry>) -> VaultResult<()> {
    let data = state.vault_data.as_mut().ok_or(VaultError::VaultLocked)?;

    for imported in imported_entries {
        let category_id = imported
            .category_name
            .as_deref()
            .map(|name| ensure_category_by_name(data, name))
            .or_else(|| Some(BUILTIN_OTHER_CATEGORY_ID.to_string()));

        let mut entry = Entry::new(imported.title);
        entry.username = imported.username;
        entry.password = imported.password;
        entry.url = imported.url;
        entry.notes = imported.notes;
        entry.favorite = imported.favorite;
        entry.category_id = category_id;
        entry.sort_order = next_entry_sort_order(&data.entries, entry.category_id.as_deref());
        data.entries.push(entry);
    }

    state.save()?;
    Ok(())
}

fn parse_bitwarden_json(content: &str) -> VaultResult<Vec<ImportedEntry>> {
    let parsed: serde_json::Value = serde_json::from_str(content)
        .map_err(|_| VaultError::ImportExport("The Bitwarden file is not valid JSON".into()))?;
    let items = parsed
        .get("items")
        .and_then(|value| value.as_array())
        .ok_or_else(|| VaultError::ImportExport("The Bitwarden export does not contain an items array".into()))?;

    let folders = parsed
        .get("folders")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|folder| {
            let id = folder.get("id")?.as_str()?.to_string();
            let name = sanitize_import_category_name(folder.get("name").and_then(|value| value.as_str()).map(str::to_string));
            name.map(|name| (id, name))
        })
        .collect::<HashMap<_, _>>();

    Ok(items
        .iter()
        .map(|item| {
            let login = item.get("login");
            let category_name = item
                .get("folderId")
                .and_then(|value| value.as_str())
                .and_then(|folder_id| folders.get(folder_id).cloned());

            ImportedEntry {
                title: sanitize_import_required_text(
                    item.get("name").and_then(|value| value.as_str()).unwrap_or("Imported Entry"),
                    MAX_TITLE_LENGTH,
                    "Imported Entry",
                ),
                username: sanitize_import_optional_text(
                    login
                        .and_then(|value| value.get("username"))
                        .and_then(|value| value.as_str())
                        .map(str::to_string),
                    MAX_USERNAME_LENGTH,
                    true,
                ),
                password: sanitize_import_optional_text(
                    login
                        .and_then(|value| value.get("password"))
                        .and_then(|value| value.as_str())
                        .map(str::to_string),
                    MAX_PASSWORD_LENGTH,
                    false,
                ),
                url: sanitize_import_url(
                    login
                        .and_then(|value| value.get("uris"))
                        .and_then(|value| value.as_array())
                        .and_then(|uris| uris.first())
                        .and_then(|uri| uri.get("uri"))
                        .and_then(|value| value.as_str())
                        .map(str::to_string),
                ),
                notes: sanitize_import_optional_text(
                    item.get("notes").and_then(|value| value.as_str()).map(str::to_string),
                    MAX_NOTES_LENGTH,
                    false,
                ),
                favorite: item
                    .get("favorite")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                category_name,
            }
        })
        .collect())
}

fn parse_keepass_xml(content: &str) -> VaultResult<Vec<ImportedEntry>> {
    let mut data = VaultData::new_empty();
    parse_keepass_xml_into_entries(content, &mut data)?;

    let categories_by_id = data
        .categories
        .iter()
        .map(|category| {
            (
                category.id.clone(),
                (category.name.clone(), category.built_in),
            )
        })
        .collect::<HashMap<_, _>>();

    Ok(std::mem::take(&mut data.entries)
        .into_iter()
        .map(|entry| ImportedEntry {
            title: entry.title,
            username: entry.username,
            password: entry.password,
            url: entry.url,
            notes: entry.notes,
            favorite: entry.favorite,
            category_name: entry.category_id.and_then(|category_id| {
                categories_by_id.get(&category_id).and_then(|(name, built_in)| {
                    if *built_in {
                        None
                    } else {
                        Some(name.clone())
                    }
                })
            }),
        })
        .collect())
}

fn parse_1password_csv(content: &str) -> VaultResult<Vec<ImportedEntry>> {
    parse_csv_entries(
        content,
        &["title", "name", "entry", "site"][..],
        &["username", "login", "email"][..],
        &["password", "passcode"][..],
        &["url", "website", "login url"][..],
        &["notes", "note"][..],
        &["category", "vault", "group"][..],
    )
}

fn parse_lastpass_csv(content: &str) -> VaultResult<Vec<ImportedEntry>> {
    parse_csv_entries(
        content,
        &["name", "title", "site"][..],
        &["username", "user", "login", "email"][..],
        &["password", "pass", "pwd"][..],
        &["url", "site", "website", "link"][..],
        &["extra", "notes", "note", "comments"][..],
        &["grouping", "folder", "category"][..],
    )
}

fn parse_dashlane_csv(content: &str) -> VaultResult<Vec<ImportedEntry>> {
    parse_csv_entries(
        content,
        &["title", "name", "website name", "item name"][..],
        &["username", "login", "email"][..],
        &["password", "pass"][..],
        &["url", "website", "login url"][..],
        &["note", "notes", "comments"][..],
        &["category", "space", "folder"][..],
    )
}

fn parse_generic_csv(content: &str) -> VaultResult<Vec<ImportedEntry>> {
    parse_csv_entries(
        content,
        &["title", "name", "entry", "site"][..],
        &["username", "user", "login", "email"][..],
        &["password", "pass", "pwd"][..],
        &["url", "uri", "website", "site", "link"][..],
        &["notes", "note", "comments", "extra"][..],
        &["category", "folder", "group"][..],
    )
}

fn parse_csv_entries(
    content: &str,
    title_headers: &[&str],
    username_headers: &[&str],
    password_headers: &[&str],
    url_headers: &[&str],
    notes_headers: &[&str],
    category_headers: &[&str],
) -> VaultResult<Vec<ImportedEntry>> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(content.as_bytes());

    let headers = reader
        .headers()
        .map_err(|_| VaultError::ImportExport("The CSV file header could not be read".into()))?
        .clone();

    let title_idx = find_header_index(&headers, title_headers);
    let username_idx = find_header_index(&headers, username_headers);
    let password_idx = find_header_index(&headers, password_headers);
    let url_idx = find_header_index(&headers, url_headers);
    let notes_idx = find_header_index(&headers, notes_headers);
    let category_idx = find_header_index(&headers, category_headers);

    let mut imported_entries = Vec::new();
    for record in reader.records() {
        let record = record
            .map_err(|_| VaultError::ImportExport("The CSV file contains an invalid row".into()))?;

        let title_cell = title_idx.and_then(|index| record.get(index)).unwrap_or("");
        let username_cell = username_idx.and_then(|index| record.get(index)).unwrap_or("");
        let password_cell = password_idx.and_then(|index| record.get(index)).unwrap_or("");
        let url_cell = url_idx.and_then(|index| record.get(index)).unwrap_or("");
        let notes_cell = notes_idx.and_then(|index| record.get(index)).unwrap_or("");

        if [title_cell, username_cell, password_cell, url_cell, notes_cell]
            .iter()
            .all(|value| value.trim().is_empty())
        {
            continue;
        }

        imported_entries.push(ImportedEntry {
            title: sanitize_import_required_text(title_cell, MAX_TITLE_LENGTH, "Imported Entry"),
            username: sanitize_import_optional_text(
                string_cell(username_idx, &record),
                MAX_USERNAME_LENGTH,
                true,
            ),
            password: sanitize_import_optional_text(
                string_cell(password_idx, &record),
                MAX_PASSWORD_LENGTH,
                false,
            ),
            url: sanitize_import_url(string_cell(url_idx, &record)),
            notes: sanitize_import_optional_text(
                string_cell(notes_idx, &record),
                MAX_NOTES_LENGTH,
                false,
            ),
            favorite: false,
            category_name: sanitize_import_category_name(string_cell(category_idx, &record)),
        });
    }

    Ok(imported_entries)
}

fn string_cell(index: Option<usize>, record: &csv::StringRecord) -> Option<String> {
    index
        .and_then(|value| record.get(value))
        .map(str::to_string)
}

fn sanitize_import_required_text(value: impl AsRef<str>, max_len: usize, fallback: &str) -> String {
    let sanitized = sanitize_import_string(value.as_ref(), max_len, true);
    if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized
    }
}

fn sanitize_import_optional_text(
    value: Option<String>,
    max_len: usize,
    trim: bool,
) -> Option<String> {
    let value = value?;
    let sanitized = sanitize_import_string(&value, max_len, trim);
    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

fn sanitize_import_category_name(value: Option<String>) -> Option<String> {
    sanitize_import_optional_text(value, MAX_CATEGORY_LENGTH, true)
}

fn sanitize_import_url(value: Option<String>) -> Option<String> {
    let sanitized = sanitize_import_optional_text(value, MAX_URL_LENGTH, true)?;
    let parsed = Url::parse(&sanitized).ok()?;
    match parsed.scheme().to_ascii_lowercase().as_str() {
        "https" | "http" | "ssh" => Some(sanitized),
        _ => None,
    }
}

fn sanitize_import_string(value: &str, max_len: usize, trim: bool) -> String {
    let without_nulls = value.replace('\0', "");
    let without_html = strip_html_tags(&without_nulls);
    let normalized = if trim {
        without_html.trim().to_string()
    } else {
        without_html
    };
    truncate_chars(normalized, max_len)
}

fn strip_html_tags(value: &str) -> String {
    let mut stripped = String::with_capacity(value.len());
    let mut in_tag = false;

    for ch in value.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => stripped.push(ch),
            _ => {}
        }
    }

    stripped
}

fn truncate_chars(value: String, max_len: usize) -> String {
    value.chars().take(max_len).collect()
}

fn dialog_file_path_to_string(file_path: FilePath) -> Option<String> {
    match file_path {
        FilePath::Path(path) => Some(path.to_string_lossy().into_owned()),
        FilePath::Url(url) => url
            .to_file_path()
            .ok()
            .map(|path| path.to_string_lossy().into_owned()),
    }
}

const MAX_TITLE_LENGTH: usize = 256;
const MAX_USERNAME_LENGTH: usize = 256;
const MAX_PASSWORD_LENGTH: usize = 1024;
const MAX_URL_LENGTH: usize = 2048;
const MAX_NOTES_LENGTH: usize = 10_000;
const MAX_IMPORT_FILE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_CATEGORY_LENGTH: usize = 64;
const MAX_TAG_LENGTH: usize = 64;
const MAX_CUSTOM_FIELD_KEY_LENGTH: usize = 128;
const MAX_CUSTOM_FIELD_VALUE_LENGTH: usize = 4096;
const MAX_CATEGORY_ID_LENGTH: usize = 128;
const MAX_EMOJI_LENGTH: usize = 8;

fn sanitize_entry_input(input: EntryInput) -> VaultResult<EntryInput> {
    Ok(EntryInput {
        title: sanitize_required_text(input.title, MAX_TITLE_LENGTH, "Title")?,
        username: sanitize_optional_text(input.username, MAX_USERNAME_LENGTH, "Username", true)?,
        password: sanitize_optional_text(input.password, MAX_PASSWORD_LENGTH, "Password", false)?,
        url: sanitize_optional_url(input.url)?,
        notes: sanitize_optional_text(input.notes, MAX_NOTES_LENGTH, "Notes", false)?,
        category_id: sanitize_optional_text(
            input.category_id,
            MAX_CATEGORY_ID_LENGTH,
            "Category",
            true,
        )?,
        tags: sanitize_tags(input.tags)?,
        custom_fields: sanitize_custom_fields(input.custom_fields)?,
        favorite: input.favorite,
    })
}

fn sanitize_category_input(input: CategoryInput) -> VaultResult<CategoryInput> {
    let color = strip_null_bytes(input.color);
    if !is_valid_hex_color(&color) {
        return Err(VaultError::Validation(
            "Category color must be a 7-character hex value like #7c6fe0".into(),
        ));
    }

    let emoji = strip_null_bytes(input.emoji).trim().to_string();
    if emoji.chars().count() > MAX_EMOJI_LENGTH {
        return Err(VaultError::Validation("Category emoji is too long".into()));
    }

    Ok(CategoryInput {
        name: sanitize_required_text(input.name, MAX_CATEGORY_LENGTH, "Category name")?,
        emoji: if emoji.is_empty() {
            "📁".to_string()
        } else {
            emoji
        },
        color,
    })
}

fn sanitize_language(language: String) -> VaultResult<String> {
    match strip_null_bytes(language).trim() {
        "en" => Ok("en".to_string()),
        "de" => Ok("de".to_string()),
        _ => Err(VaultError::Validation("Unsupported language".into())),
    }
}

fn sanitize_required_text(value: String, max_len: usize, field: &str) -> VaultResult<String> {
    let sanitized = strip_null_bytes(value);
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        return Err(VaultError::Validation(format!("{field} is required")));
    }
    enforce_max_length(trimmed, max_len, field)?;
    Ok(trimmed.to_string())
}

fn sanitize_optional_text(
    value: Option<String>,
    max_len: usize,
    field: &str,
    trim: bool,
) -> VaultResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let sanitized = strip_null_bytes(value);
    let normalized = if trim {
        sanitized.trim().to_string()
    } else {
        sanitized
    };

    if normalized.trim().is_empty() {
        return Ok(None);
    }

    enforce_max_length(&normalized, max_len, field)?;
    Ok(Some(normalized))
}

fn sanitize_optional_url(value: Option<String>) -> VaultResult<Option<String>> {
    let Some(url) = sanitize_optional_text(value, MAX_URL_LENGTH, "URL", true)? else {
        return Ok(None);
    };

    let parsed = Url::parse(&url)
        .map_err(|_| VaultError::Validation("URL must be a well-formed absolute URL".into()))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ssh") {
        return Err(VaultError::Validation(
            "URL must start with https://, http://, or ssh://".into(),
        ));
    }

    Ok(Some(url))
}

fn sanitize_tags(tags: Vec<String>) -> VaultResult<Vec<String>> {
    let mut sanitized = Vec::new();
    let mut seen = HashSet::new();

    for tag in tags {
        let Some(tag) = sanitize_optional_text(Some(tag), MAX_TAG_LENGTH, "Tag", true)? else {
            continue;
        };
        let fingerprint = tag.to_lowercase();
        if seen.insert(fingerprint) {
            sanitized.push(tag);
        }
    }

    Ok(sanitized)
}

fn sanitize_custom_fields(fields: Vec<CustomField>) -> VaultResult<Vec<CustomField>> {
    let mut sanitized = Vec::new();
    for field in fields {
        let Some(key) = sanitize_optional_text(
            Some(field.key),
            MAX_CUSTOM_FIELD_KEY_LENGTH,
            "Custom field key",
            true,
        )? else {
            continue;
        };
        let value = sanitize_optional_text(
            Some(field.value),
            MAX_CUSTOM_FIELD_VALUE_LENGTH,
            "Custom field value",
            false,
        )?
        .unwrap_or_default();
        sanitized.push(CustomField {
            key,
            value,
            hidden: field.hidden,
        });
    }
    Ok(sanitized)
}

fn strip_null_bytes(mut value: String) -> String {
    value.retain(|ch| ch != '\0');
    value
}

fn enforce_max_length(value: &str, max_len: usize, field: &str) -> VaultResult<()> {
    if value.chars().count() > max_len {
        Err(VaultError::Validation(format!(
            "{field} exceeds the maximum length of {max_len} characters"
        )))
    } else {
        Ok(())
    }
}

fn is_valid_hex_color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value.chars().skip(1).all(|ch| ch.is_ascii_hexdigit())
}

fn normalize_existing_category_id(
    category_id: Option<String>,
    categories: &[Category],
) -> Option<String> {
    let category_id = category_id?;
    if categories.iter().any(|category| category.id == category_id) {
        Some(category_id)
    } else {
        None
    }
}

fn lockout_tier_label(tier: u8) -> &'static str {
    match tier {
        1 => "12 hours",
        2 => "24 hours",
        _ => "1 week",
    }
}

fn normalize_category_order(categories: &mut [Category]) {
    categories.sort_by_key(|category| category.sort_order);
    for (index, category) in categories.iter_mut().enumerate() {
        category.sort_order = index as u32;
    }
}

fn delete_category_from_data(data: &mut VaultData, id: &str) -> VaultResult<()> {
    if let Some(category) = data.categories.iter().find(|category| category.id == id) {
        if category.built_in {
            return Err(VaultError::Validation("Cannot delete built-in categories".into()));
        }
    }

    for entry in &mut data.entries {
        if entry.category_id.as_deref() == Some(id) {
            entry.category_id = Some(BUILTIN_OTHER_CATEGORY_ID.to_string());
        }
    }

    data.categories.retain(|category| category.id != id);
    normalize_category_order(&mut data.categories);
    compact_entry_sort_orders(&mut data.entries);
    Ok(())
}

fn next_entry_sort_order(entries: &[Entry], category_id: Option<&str>) -> u32 {
    entries
        .iter()
        .filter(|entry| entry.category_id.as_deref() == category_id)
        .map(|entry| entry.sort_order)
        .max()
        .map_or(0, |value| value.saturating_add(1))
}

fn next_entry_sort_order_excluding(entries: &[Entry], category_id: Option<&str>, entry_id: &str) -> u32 {
    entries
        .iter()
        .filter(|entry| entry.id != entry_id && entry.category_id.as_deref() == category_id)
        .map(|entry| entry.sort_order)
        .max()
        .map_or(0, |value| value.saturating_add(1))
}

fn sorted_entry_ids_for_category(
    entries: &[Entry],
    category_id: Option<&str>,
    exclude_entry_id: Option<&str>,
) -> Vec<String> {
    let mut filtered = entries
        .iter()
        .filter(|entry| entry.category_id.as_deref() == category_id)
        .filter(|entry| exclude_entry_id != Some(entry.id.as_str()))
        .collect::<Vec<_>>();
    filtered.sort_by(|left, right| left.sort_order.cmp(&right.sort_order));
    filtered.into_iter().map(|entry| entry.id.clone()).collect()
}

fn apply_entry_order_for_category(
    entries: &mut [Entry],
    category_id: Option<&str>,
    ordered_ids: &[String],
) {
    let order_map = ordered_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index as u32))
        .collect::<HashMap<_, _>>();

    for entry in entries
        .iter_mut()
        .filter(|entry| entry.category_id.as_deref() == category_id)
    {
        if let Some(sort_order) = order_map.get(entry.id.as_str()) {
            entry.sort_order = *sort_order;
        }
    }
}

fn compact_single_category(entries: &mut [Entry], category_id: Option<&str>) {
    let ordered_ids = sorted_entry_ids_for_category(entries, category_id, None);
    apply_entry_order_for_category(entries, category_id, &ordered_ids);
}

fn compact_entry_sort_orders(entries: &mut [Entry]) {
    let mut categories = entries
        .iter()
        .map(|entry| entry.category_id.clone())
        .collect::<HashSet<_>>();

    for category_id in categories.drain() {
        compact_single_category(entries, category_id.as_deref());
    }
}

fn place_entry_in_category(
    data: &mut VaultData,
    entry_id: &str,
    new_category_id: Option<String>,
    insert_index: usize,
) -> VaultResult<()> {
    let entry_index = data
        .entries
        .iter()
        .position(|entry| entry.id == entry_id)
        .ok_or_else(|| VaultError::EntryNotFound(entry_id.to_string()))?;
    let normalized_category_id = normalize_existing_category_id(new_category_id, &data.categories)
        .or_else(|| Some(BUILTIN_OTHER_CATEGORY_ID.to_string()));
    let previous_category_id = data.entries[entry_index].category_id.clone();
    data.entries[entry_index].category_id = normalized_category_id.clone();

    let destination_ids =
        sorted_entry_ids_for_category(&data.entries, normalized_category_id.as_deref(), Some(entry_id));
    let clamped_index = usize::min(insert_index, destination_ids.len());
    let mut reordered_ids = destination_ids;
    reordered_ids.insert(clamped_index, entry_id.to_string());

    apply_entry_order_for_category(
        &mut data.entries,
        normalized_category_id.as_deref(),
        &reordered_ids,
    );

    if previous_category_id != normalized_category_id {
        compact_single_category(&mut data.entries, previous_category_id.as_deref());
    }

    Ok(())
}

fn is_valid_auto_lock(minutes: u32) -> bool {
    matches!(minutes, 0 | 1 | 5 | 10 | 30 | 60)
}

fn is_valid_clipboard_timeout(seconds: u32) -> bool {
    matches!(seconds, 60 | 300 | 600 | 1800)
}

fn find_header_index(headers: &csv::StringRecord, names: &[&str]) -> Option<usize> {
    for (index, header) in headers.iter().enumerate() {
        let lower = header.to_lowercase();
        if names.iter().any(|name| lower.contains(name)) {
            return Some(index);
        }
    }
    None
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn append_xml_text_element(xml: &mut String, tag: &str, value: &str) {
    xml.push('<');
    xml.push_str(tag);
    xml.push('>');
    xml.push_str(&xml_escape(value));
    xml.push_str("</");
    xml.push_str(tag);
    xml.push('>');
}

fn append_keepass_string(xml: &mut String, key: &str, value: &str) {
    if value.trim().is_empty() {
        return;
    }

    xml.push_str("<String>");
    append_xml_text_element(xml, "Key", key);
    append_xml_text_element(xml, "Value", value);
    xml.push_str("</String>");
}

fn append_keepass_entry(xml: &mut String, entry: &Entry) {
    xml.push_str("<Entry>");
    append_xml_text_element(xml, "UUID", &entry.id);
    append_keepass_string(xml, "Title", &entry.title);
    if let Some(username) = entry.username.as_deref() {
        append_keepass_string(xml, "UserName", username);
    }
    if let Some(password) = entry.password.as_deref() {
        append_keepass_string(xml, "Password", password);
    }
    if let Some(url) = entry.url.as_deref() {
        append_keepass_string(xml, "URL", url);
    }
    if let Some(notes) = entry.notes.as_deref() {
        append_keepass_string(xml, "Notes", notes);
    }
    if !entry.tags.is_empty() {
        append_keepass_string(xml, "Tags", &entry.tags.join(", "));
    }
    if entry.favorite {
        append_keepass_string(xml, "VaultGuardFavorite", "true");
    }
    for field in &entry.custom_fields {
        append_keepass_string(xml, &field.key, &field.value);
    }

    xml.push_str("<Times>");
    append_xml_text_element(xml, "CreationTime", &entry.created_at.to_rfc3339());
    append_xml_text_element(xml, "LastModificationTime", &entry.modified_at.to_rfc3339());
    append_xml_text_element(xml, "LastAccessTime", &entry.accessed_at.to_rfc3339());
    xml.push_str("</Times>");
    xml.push_str("</Entry>");
}

fn build_keepass_xml(data: &VaultData) -> String {
    let mut xml = String::new();
    xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push_str("<KeePassFile><Meta>");
    append_xml_text_element(&mut xml, "Generator", "VaultGuard");
    append_xml_text_element(&mut xml, "DatabaseName", "VaultGuard Export");
    xml.push_str("</Meta><Root><Group>");
    append_xml_text_element(&mut xml, "Name", "VaultGuard Export");

    let mut categories = data.categories.clone();
    categories.sort_by_key(|category| category.sort_order);

    for category in &categories {
        let mut entries = data
            .entries
            .iter()
            .filter(|entry| entry.category_id.as_deref() == Some(category.id.as_str()))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.sort_order);

        if entries.is_empty() {
            continue;
        }

        xml.push_str("<Group>");
        append_xml_text_element(&mut xml, "Name", &category.name);
        for entry in entries {
            append_keepass_entry(&mut xml, entry);
        }
        xml.push_str("</Group>");
    }

    let uncategorized = data
        .entries
        .iter()
        .filter(|entry| entry.category_id.is_none())
        .collect::<Vec<_>>();
    if !uncategorized.is_empty() {
        xml.push_str("<Group>");
        append_xml_text_element(&mut xml, "Name", "Unsorted");
        for entry in uncategorized {
            append_keepass_entry(&mut xml, entry);
        }
        xml.push_str("</Group>");
    }

    xml.push_str("</Group></Root></KeePassFile>");
    xml
}

#[derive(Default)]
struct KeepassImportEntry {
    title: Option<String>,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    custom_fields: Vec<CustomField>,
    favorite: bool,
    created_at: Option<DateTime<Utc>>,
    modified_at: Option<DateTime<Utc>>,
    accessed_at: Option<DateTime<Utc>>,
}

impl KeepassImportEntry {
    fn apply_string_field(&mut self, key: &str, value: String) {
        match key {
            "Title" => self.title = Some(value),
            "UserName" | "Username" | "User Name" => self.username = Some(value),
            "Password" => self.password = Some(value),
            "URL" | "Url" => self.url = Some(value),
            "Notes" => self.notes = Some(value),
            "Tags" => {
                self.tags = value
                    .split(',')
                    .map(str::trim)
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            "VaultGuardFavorite" => {
                self.favorite = matches!(value.as_str(), "true" | "True" | "1");
            }
            _ if !key.trim().is_empty() => {
                self.custom_fields.push(CustomField {
                    key: key.to_string(),
                    value,
                    hidden: matches!(key, "Password" | "VaultGuardFavorite"),
                });
            }
            _ => {}
        }
    }

    fn into_entry(self, category_id: Option<String>) -> VaultResult<Entry> {
        let now = Utc::now();
        let entry = Entry {
            id: uuid::Uuid::new_v4().to_string(),
            title: sanitize_import_required_text(
                self.title.unwrap_or_else(|| "Imported Entry".to_string()),
                MAX_TITLE_LENGTH,
                "Imported Entry",
            ),
            username: sanitize_import_optional_text(self.username, MAX_USERNAME_LENGTH, true),
            password: sanitize_import_optional_text(self.password, MAX_PASSWORD_LENGTH, false),
            url: sanitize_import_url(self.url),
            notes: sanitize_import_optional_text(self.notes, MAX_NOTES_LENGTH, false),
            category_id,
            tags: self
                .tags
                .into_iter()
                .filter_map(|tag| sanitize_import_optional_text(Some(tag), MAX_TAG_LENGTH, true))
                .collect(),
            custom_fields: self
                .custom_fields
                .into_iter()
                .filter_map(|field| {
                    let key =
                        sanitize_import_optional_text(Some(field.key), MAX_CUSTOM_FIELD_KEY_LENGTH, true)?;
                    let value = sanitize_import_optional_text(
                        Some(field.value),
                        MAX_CUSTOM_FIELD_VALUE_LENGTH,
                        false,
                    )
                    .unwrap_or_default();
                    Some(CustomField {
                        key,
                        value,
                        hidden: field.hidden,
                    })
                })
                .collect(),
            password_history: Vec::new(),
            favorite: self.favorite,
            created_at: self.created_at.unwrap_or(now),
            modified_at: self.modified_at.unwrap_or(now),
            accessed_at: self.accessed_at.unwrap_or(now),
            sort_order: 0,
        };

        Ok(entry)
    }
}

fn parse_keepass_xml_into_entries(xml_content: &str, data: &mut VaultData) -> VaultResult<u32> {
    let lowered = xml_content.to_ascii_lowercase();
    if lowered.contains("<!doctype") || lowered.contains("<!entity") {
        return Err(VaultError::ImportExport(
            "KeePass XML files with external entities are not supported".into(),
        ));
    }

    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut path = Vec::<String>::new();
    let mut group_stack = Vec::<String>::new();
    let mut current_field_key: Option<String> = None;
    let mut current_entry: Option<KeepassImportEntry> = None;
    let mut count = 0u32;
    let mut saw_root = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(event)) => {
                let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
                if path.is_empty() {
                    if name != "KeePassFile" {
                        return Err(VaultError::ImportExport(
                            "KeePass XML root element must be <KeePassFile>".into(),
                        ));
                    }
                    saw_root = true;
                }
                if name == "Group" && current_entry.is_none() {
                    group_stack.push(String::new());
                }
                if name == "Entry" {
                    if current_entry.is_some() {
                        return Err(VaultError::ImportExport(
                            "KeePass XML contains an invalid nested <Entry> element".into(),
                        ));
                    }
                    current_entry = Some(KeepassImportEntry::default());
                    current_field_key = None;
                }
                path.push(name);
            }
            Ok(Event::Empty(event)) => {
                let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
                if path.is_empty() && name != "KeePassFile" {
                    return Err(VaultError::ImportExport(
                        "KeePass XML root element must be <KeePassFile>".into(),
                    ));
                }
                if name == "KeePassFile" {
                    saw_root = true;
                }
            }
            Ok(Event::End(event)) => {
                let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
                let current_path = path
                    .last()
                    .ok_or_else(|| VaultError::ImportExport("Unexpected closing tag in KeePass XML".into()))?;
                if current_path != &name {
                    return Err(VaultError::ImportExport(format!(
                        "Malformed KeePass XML: expected closing tag for <{}> but found </{}>",
                        current_path, name
                    )));
                }

                if name == "Entry" {
                    if let Some(imported) = current_entry.take() {
                        let category_name = resolved_group_name(&group_stack);
                        let category_id = category_name
                            .as_deref()
                            .map(|name| ensure_category_by_name(data, name));
                        let mut entry = imported.into_entry(category_id)?;
                        entry.sort_order =
                            next_entry_sort_order(&data.entries, entry.category_id.as_deref());
                        data.entries.push(entry);
                        count += 1;
                    }
                }

                if name == "String" {
                    current_field_key = None;
                }

                let _ = path.pop();

                if name == "Group" && current_entry.is_none() {
                    let _ = group_stack.pop();
                }
            }
            Ok(Event::Text(event)) => {
                let text = event.decode().map_err(|e| {
                    VaultError::ImportExport(format!("Failed to decode KeePass XML text: {}", e))
                })?;
                let text = text.into_owned();

                let current = path.last().map(String::as_str);
                let parent = path.iter().rev().nth(1).map(String::as_str);

                match (current, parent, current_entry.as_mut()) {
                    (Some("Name"), Some("Group"), None) => {
                        if let Some(group_name) = group_stack.last_mut() {
                            if group_name.is_empty() {
                                *group_name = text;
                            }
                        }
                    }
                    (Some("Key"), Some("String"), Some(_)) => {
                        current_field_key = Some(text);
                    }
                    (Some("Value"), Some("String"), Some(entry)) => {
                        if let Some(key) = current_field_key.as_deref() {
                            entry.apply_string_field(key, text);
                        }
                    }
                    (Some("CreationTime"), Some("Times"), Some(entry)) => {
                        entry.created_at = parse_xml_datetime(&text);
                    }
                    (Some("LastModificationTime"), Some("Times"), Some(entry)) => {
                        entry.modified_at = parse_xml_datetime(&text);
                    }
                    (Some("LastAccessTime"), Some("Times"), Some(entry)) => {
                        entry.accessed_at = parse_xml_datetime(&text);
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => {
                if !saw_root {
                    return Err(VaultError::ImportExport(
                        "KeePass XML does not contain a <KeePassFile> root element".into(),
                    ));
                }
                if !path.is_empty() || current_entry.is_some() {
                    return Err(VaultError::ImportExport(
                        "Malformed KeePass XML: document ended unexpectedly".into(),
                    ));
                }
                break;
            }
            Ok(_) => {}
            Err(error) => {
                return Err(VaultError::ImportExport(format!(
                    "KeePass XML parse error at {}: {}",
                    reader.error_position(),
                    error
                )))
            }
        }

        buf.clear();
    }

    Ok(count)
}

fn parse_xml_datetime(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

fn resolved_group_name(group_stack: &[String]) -> Option<String> {
    if group_stack.len() > 1 {
        return group_stack
            .iter()
            .rev()
            .find(|name| !name.trim().is_empty())
            .cloned();
    }

    group_stack.first().and_then(|name| {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("VaultGuard Export") {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn ensure_category_by_name(data: &mut VaultData, name: &str) -> String {
    if let Some(existing) = data
        .categories
        .iter()
        .find(|category| category.name.eq_ignore_ascii_case(name))
    {
        return existing.id.clone();
    }

    let category = Category {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        emoji: "📁".to_string(),
        color: "#6b8fa3".to_string(),
        sort_order: data.categories.len() as u32,
        built_in: false,
    };
    let category_id = category.id.clone();
    data.categories.push(category);
    category_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn make_entry(id: &str, title: &str, category_id: &str, sort_order: u32) -> Entry {
        let mut entry = Entry::new(title.to_string());
        entry.id = id.to_string();
        entry.category_id = Some(category_id.to_string());
        entry.sort_order = sort_order;
        entry
    }

    #[test]
    fn keepass_export_contains_entry_fields() {
        let mut data = VaultData::new_empty();
        let mut entry = Entry::new("Example".to_string());
        entry.username = Some("alice@example.com".to_string());
        entry.password = Some("S3cret!".to_string());
        entry.url = Some("https://example.com".to_string());
        entry.notes = Some("note".to_string());
        data.entries.push(entry);

        let xml = build_keepass_xml(&data);
        assert!(xml.contains("<KeePassFile>"));
        assert!(xml.contains("alice@example.com"));
        assert!(xml.contains("https://example.com"));
    }

    #[test]
    fn malformed_keepass_xml_is_rejected() {
        let mut data = VaultData::new_empty();
        let result = parse_keepass_xml_into_entries("<KeePassFile><Entry>", &mut data);
        assert!(result.is_err());
    }

    #[test]
    fn keepass_roundtrip_restores_entry() {
        let mut original = VaultData::new_empty();
        let mut entry = Entry::new("Roundtrip".to_string());
        entry.username = Some("root".to_string());
        entry.password = Some("Sup3rS3cret!".to_string());
        entry.notes = Some("ssh".to_string());
        original.entries.push(entry);

        let xml = build_keepass_xml(&original);

        let mut restored = VaultData::new_empty();
        let count = parse_keepass_xml_into_entries(&xml, &mut restored)
            .expect("test should parse KeePass XML");
        assert_eq!(count, 1);
        assert_eq!(restored.entries[0].title, "Roundtrip");
        assert_eq!(restored.entries[0].username.as_deref(), Some("root"));
    }

    #[test]
    fn bitwarden_parser_imports_minimal_entry() {
        let imported = parse_bitwarden_json(
            r#"{
                "folders":[{"id":"folder-1","name":"Work"}],
                "items":[
                    {
                        "name":"Example",
                        "favorite":true,
                        "folderId":"folder-1",
                        "notes":"<b>note</b>",
                        "login":{
                            "username":"alice@example.com",
                            "password":"Secret!123",
                            "uris":[{"uri":"https://example.com"}]
                        }
                    }
                ]
            }"#,
        )
        .expect("test should parse Bitwarden JSON");

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title, "Example");
        assert_eq!(imported[0].notes.as_deref(), Some("note"));
        assert_eq!(imported[0].category_name.as_deref(), Some("Work"));
        assert!(imported[0].favorite);
    }

    #[test]
    fn keepass_parser_imports_minimal_entry() {
        let imported = parse_keepass_xml(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <KeePassFile>
              <Root>
                <Group>
                  <Name>Imported Group</Name>
                  <Entry>
                    <String><Key>Title</Key><Value>SSH Key</Value></String>
                    <String><Key>UserName</Key><Value>deploy</Value></String>
                    <String><Key>Password</Key><Value>p@ss</Value></String>
                    <String><Key>URL</Key><Value>ssh://example.com</Value></String>
                  </Entry>
                </Group>
              </Root>
            </KeePassFile>"#,
        )
        .expect("test should parse KeePass XML");

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title, "SSH Key");
        assert_eq!(imported[0].category_name.as_deref(), Some("Imported Group"));
        assert_eq!(imported[0].url.as_deref(), Some("ssh://example.com"));
    }

    #[test]
    fn one_password_csv_parser_imports_minimal_entry() {
        let imported = parse_1password_csv(
            "Title,Url,Username,Password,Notes\nExample,https://example.com,alice,Secret!123,hello\n",
        )
        .expect("test should parse 1Password CSV");

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title, "Example");
        assert_eq!(imported[0].username.as_deref(), Some("alice"));
    }

    #[test]
    fn lastpass_csv_parser_imports_minimal_entry() {
        let imported = parse_lastpass_csv(
            "name,url,username,password,extra,grouping\nExample,https://example.com,alice,Secret!123,note,Shared\n",
        )
        .expect("test should parse LastPass CSV");

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].category_name.as_deref(), Some("Shared"));
        assert_eq!(imported[0].notes.as_deref(), Some("note"));
    }

    #[test]
    fn dashlane_csv_parser_imports_minimal_entry() {
        let imported = parse_dashlane_csv(
            "title,website,login,password,note,category\nExample,https://example.com,alice,Secret!123,hello,Finance\n",
        )
        .expect("test should parse Dashlane CSV");

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].category_name.as_deref(), Some("Finance"));
    }

    #[test]
    fn generic_csv_parser_imports_minimal_entry() {
        let imported = parse_generic_csv(
            "title,username,password,url,notes\nExample,alice,Secret!123,https://example.com,hello\n",
        )
        .expect("test should parse generic CSV");

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title, "Example");
        assert_eq!(imported[0].url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn built_in_category_deletion_is_rejected() {
        let mut data = VaultData::new_empty();
        let result = delete_category_from_data(&mut data, BUILTIN_LOGIN_CATEGORY_ID);
        assert!(matches!(result, Err(VaultError::Validation(_))));
    }

    #[test]
    fn custom_category_deletion_reassigns_entries_to_other() {
        let mut data = VaultData::new_empty();
        data.categories.push(Category {
            id: "custom-dev".to_string(),
            name: "Dev".to_string(),
            emoji: "💻".to_string(),
            color: "#5fb8a6".to_string(),
            sort_order: 3,
            built_in: false,
        });

        let mut entry = Entry::new("Server".to_string());
        entry.category_id = Some("custom-dev".to_string());
        data.entries.push(entry);

        delete_category_from_data(&mut data, "custom-dev")
            .expect("test should delete custom category");
        assert_eq!(
            data.entries[0].category_id.as_deref(),
            Some(BUILTIN_OTHER_CATEGORY_ID)
        );
        assert!(!data.categories.iter().any(|category| category.id == "custom-dev"));
    }

    #[test]
    fn moving_entry_to_category_appends_and_compacts_source_order() {
        let mut data = VaultData::new_empty();
        data.entries = vec![
            make_entry("login-a", "Login A", BUILTIN_LOGIN_CATEGORY_ID, 0),
            make_entry("login-b", "Login B", BUILTIN_LOGIN_CATEGORY_ID, 1),
            make_entry("api-a", "API A", BUILTIN_API_KEYS_CATEGORY_ID, 0),
        ];

        place_entry_in_category(
            &mut data,
            "login-b",
            Some(BUILTIN_API_KEYS_CATEGORY_ID.to_string()),
            usize::MAX,
        )
        .expect("test should move entry into target category");

        let login_ids =
            sorted_entry_ids_for_category(&data.entries, Some(BUILTIN_LOGIN_CATEGORY_ID), None);
        let api_ids =
            sorted_entry_ids_for_category(&data.entries, Some(BUILTIN_API_KEYS_CATEGORY_ID), None);

        assert_eq!(login_ids, vec!["login-a".to_string()]);
        assert_eq!(api_ids, vec!["api-a".to_string(), "login-b".to_string()]);
        assert_eq!(
            data.entries
                .iter()
                .find(|entry| entry.id == "login-a")
                .expect("test should keep login-a entry")
                .sort_order,
            0
        );
        assert_eq!(
            data.entries
                .iter()
                .find(|entry| entry.id == "login-b")
                .expect("test should keep login-b entry")
                .sort_order,
            1
        );
    }

    #[test]
    fn reorder_entry_before_updates_order() {
        let mut data = VaultData::new_empty();
        data.entries = vec![
            make_entry("a", "A", BUILTIN_LOGIN_CATEGORY_ID, 0),
            make_entry("b", "B", BUILTIN_LOGIN_CATEGORY_ID, 1),
            make_entry("c", "C", BUILTIN_LOGIN_CATEGORY_ID, 2),
        ];

        let ordered_ids =
            sorted_entry_ids_for_category(&data.entries, Some(BUILTIN_LOGIN_CATEGORY_ID), Some("c"));
        let target_index = ordered_ids
            .iter()
            .position(|id| id == "a")
            .expect("test should locate reorder target");
        place_entry_in_category(
            &mut data,
            "c",
            Some(BUILTIN_LOGIN_CATEGORY_ID.to_string()),
            target_index,
        )
        .expect("test should reorder entry before target");

        let final_ids =
            sorted_entry_ids_for_category(&data.entries, Some(BUILTIN_LOGIN_CATEGORY_ID), None);
        assert_eq!(
            final_ids,
            vec!["c".to_string(), "a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn reorder_entry_after_updates_order() {
        let mut data = VaultData::new_empty();
        data.entries = vec![
            make_entry("a", "A", BUILTIN_LOGIN_CATEGORY_ID, 0),
            make_entry("b", "B", BUILTIN_LOGIN_CATEGORY_ID, 1),
            make_entry("c", "C", BUILTIN_LOGIN_CATEGORY_ID, 2),
        ];

        let ordered_ids =
            sorted_entry_ids_for_category(&data.entries, Some(BUILTIN_LOGIN_CATEGORY_ID), Some("a"));
        let target_index = ordered_ids
            .iter()
            .position(|id| id == "b")
            .expect("test should locate reorder target");
        place_entry_in_category(
            &mut data,
            "a",
            Some(BUILTIN_LOGIN_CATEGORY_ID.to_string()),
            target_index + 1,
        )
        .expect("test should reorder entry after target");

        let final_ids =
            sorted_entry_ids_for_category(&data.entries, Some(BUILTIN_LOGIN_CATEGORY_ID), None);
        assert_eq!(
            final_ids,
            vec!["b".to_string(), "a".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn app_state_lock_clears_session_and_rejects_authorization() {
        let mut state = AppState::new(std::env::temp_dir().join("vaultguard-lock-test.enc"));
        state.kek = Some(Zeroizing::new([1u8; KEY_SIZE]));
        state.dek = Some(Zeroizing::new([2u8; KEY_SIZE]));
        state.salt = Some([3u8; SALT_SIZE]);
        state.vault_data = Some(VaultData::new_empty());
        state.session_token = Some(Zeroizing::new("session-token".to_string()));

        assert!(state.ensure_authorized("session-token").is_ok());
        state.lock();

        assert!(state.kek.is_none());
        assert!(state.dek.is_none());
        assert!(state.salt.is_none());
        assert!(state.vault_data.is_none());
        assert!(state.session_token.is_none());
        assert!(matches!(
            state.ensure_authorized("session-token"),
            Err(VaultError::Unauthorized)
        ));
    }

    #[test]
    fn sanitize_entry_input_strips_null_bytes_and_blocks_dangerous_urls() {
        let sanitized = sanitize_entry_input(EntryInput {
            title: "Ti\0tle".to_string(),
            username: Some("  ali\0ce@example.com  ".to_string()),
            password: Some("pw\0value".to_string()),
            url: Some("https://example.com".to_string()),
            notes: Some("no\0tes".to_string()),
            category_id: Some(BUILTIN_LOGIN_CATEGORY_ID.to_string()),
            tags: vec![" wor\0k ".to_string()],
            favorite: false,
            custom_fields: vec![CustomField {
                key: "api\0key".to_string(),
                value: "<script>alert(1)</script>".to_string(),
                hidden: true,
            }],
        })
        .expect("test should sanitize entry input");

        assert_eq!(sanitized.title, "Title");
        assert_eq!(sanitized.username.as_deref(), Some("alice@example.com"));
        assert_eq!(sanitized.password.as_deref(), Some("pwvalue"));
        assert_eq!(sanitized.notes.as_deref(), Some("notes"));
        assert_eq!(sanitized.tags, vec!["work".to_string()]);
        assert_eq!(sanitized.custom_fields[0].key, "apikey");
        assert_eq!(sanitized.custom_fields[0].value, "<script>alert(1)</script>");

        let rejected = sanitize_entry_input(EntryInput {
            title: "Example".to_string(),
            username: None,
            password: None,
            url: Some("javascript:alert(1)".to_string()),
            notes: None,
            category_id: Some(BUILTIN_LOGIN_CATEGORY_ID.to_string()),
            tags: Vec::new(),
            custom_fields: Vec::new(),
            favorite: false,
        });
        assert!(matches!(rejected, Err(VaultError::Validation(_))));
    }
}
