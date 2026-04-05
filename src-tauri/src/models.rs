//! Data models for VaultGuard
//!
//! All models derive Serialize/Deserialize for JSON storage and Tauri IPC.
//! Sensitive fields are stored encrypted at the vault level.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zeroize::Zeroize;

pub const BUILTIN_LOGIN_CATEGORY_ID: &str = "builtin-login";
pub const BUILTIN_API_KEYS_CATEGORY_ID: &str = "builtin-apikeys";
pub const BUILTIN_OTHER_CATEGORY_ID: &str = "builtin-other";

/// Complete vault data structure — the entire application state when unlocked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub entries: Vec<Entry>,
    pub categories: Vec<Category>,
    pub trash: Vec<TrashEntry>,
    pub settings: VaultSettings,
}

impl VaultData {
    pub fn new_empty() -> Self {
        VaultData {
            entries: Vec::new(),
            categories: default_categories(),
            trash: Vec::new(),
            settings: VaultSettings::default(),
        }
    }
}

impl Drop for VaultData {
    fn drop(&mut self) {
        // Zeroize all sensitive data when VaultData is dropped
        for entry in &mut self.entries {
            entry.title.zeroize();
            if let Some(ref mut u) = entry.username {
                u.zeroize();
            }
            if let Some(ref mut p) = entry.password {
                p.zeroize();
            }
            if let Some(ref mut url) = entry.url {
                url.zeroize();
            }
            if let Some(ref mut n) = entry.notes {
                n.zeroize();
            }
            for tag in &mut entry.tags {
                tag.zeroize();
            }
            for field in &mut entry.custom_fields {
                field.key.zeroize();
                field.value.zeroize();
            }
            for hist in &mut entry.password_history {
                hist.password.zeroize();
            }
        }
        for trash_entry in &mut self.trash {
            trash_entry.entry.title.zeroize();
            if let Some(ref mut u) = trash_entry.entry.username {
                u.zeroize();
            }
            if let Some(ref mut p) = trash_entry.entry.password {
                p.zeroize();
            }
            if let Some(ref mut url) = trash_entry.entry.url {
                url.zeroize();
            }
            if let Some(ref mut n) = trash_entry.entry.notes {
                n.zeroize();
            }
        }
    }
}

/// A single password/credential entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category_id: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: Vec<CustomField>,
    pub password_history: Vec<PasswordHistoryItem>,
    pub favorite: bool,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
    #[serde(default)]
    pub sort_order: u32,
}

impl Entry {
    pub fn new(title: String) -> Self {
        let now = Utc::now();
        Entry {
            id: uuid::Uuid::new_v4().to_string(),
            title,
            username: None,
            password: None,
            url: None,
            notes: None,
            category_id: None,
            tags: Vec::new(),
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            favorite: false,
            created_at: now,
            modified_at: now,
            accessed_at: now,
            sort_order: 0,
        }
    }

    /// Push a password to history, keeping only the last 10 entries
    pub fn push_password_history(&mut self, old_password: &str) {
        self.password_history.push(PasswordHistoryItem {
            password: old_password.to_string(),
            changed_at: Utc::now(),
        });
        // Keep only last 10
        if self.password_history.len() > 10 {
            let excess = self.password_history.len() - 10;
            // Zeroize removed entries
            for item in self.password_history.drain(0..excess) {
                let mut pw = item.password;
                pw.zeroize();
            }
        }
    }
}

/// Custom key-value field for an entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub key: String,
    pub value: String,
    pub hidden: bool,
}

/// Historical password entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistoryItem {
    pub password: String,
    pub changed_at: DateTime<Utc>,
}

/// Category/folder for organizing entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub emoji: String,
    pub color: String,
    #[serde(default, alias = "order")]
    pub sort_order: u32,
    #[serde(default, alias = "is_builtin")]
    pub built_in: bool,
}

/// Trash entry with deletion timestamp (30-day recovery)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrashEntry {
    pub entry: Entry,
    pub deleted_at: DateTime<Utc>,
}

impl TrashEntry {
    /// Check if this entry has expired (30+ days in trash)
    pub fn is_expired(&self) -> bool {
        let days = (Utc::now() - self.deleted_at).num_days();
        days >= 30
    }
}

/// Vault-level settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    pub auto_lock_minutes: u32,
    #[serde(default = "default_clipboard_mode")]
    pub clipboard_mode: ClipboardMode,
    #[serde(default = "default_clipboard_timeout_secs")]
    pub clipboard_timeout_secs: u32,
    #[serde(default)]
    pub clipboard_remember_choice: bool,
    pub language: String,
    pub show_favicons: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardMode {
    Timed,
    Manual,
    Never,
}

impl Default for VaultSettings {
    fn default() -> Self {
        VaultSettings {
            auto_lock_minutes: 5,
            clipboard_mode: ClipboardMode::Timed,
            clipboard_timeout_secs: 300,
            clipboard_remember_choice: false,
            language: "en".to_string(),
            show_favicons: true,
        }
    }
}

fn default_clipboard_mode() -> ClipboardMode {
    ClipboardMode::Timed
}

fn default_clipboard_timeout_secs() -> u32 {
    300
}

/// Create the default built-in categories
pub fn default_categories() -> Vec<Category> {
    vec![
        Category {
            id: BUILTIN_LOGIN_CATEGORY_ID.to_string(),
            name: "Login".to_string(),
            emoji: "🔑".to_string(),
            color: "#7c6fe0".to_string(),
            sort_order: 0,
            built_in: true,
        },
        Category {
            id: BUILTIN_API_KEYS_CATEGORY_ID.to_string(),
            name: "API Keys".to_string(),
            emoji: "🔐".to_string(),
            color: "#4ca8e0".to_string(),
            sort_order: 1,
            built_in: true,
        },
        Category {
            id: BUILTIN_OTHER_CATEGORY_ID.to_string(),
            name: "Other".to_string(),
            emoji: "📁".to_string(),
            color: "#60b87a".to_string(),
            sort_order: 2,
            built_in: true,
        },
    ]
}

pub fn normalize_vault_data(vault: &mut VaultData) -> bool {
    let defaults = default_categories();
    let before_categories = vault
        .categories
        .iter()
        .map(category_signature)
        .collect::<Vec<_>>();
    let before_entry_categories = vault
        .entries
        .iter()
        .map(|entry| entry.category_id.clone())
        .collect::<Vec<_>>();
    let before_trash_categories = vault
        .trash
        .iter()
        .map(|item| item.entry.category_id.clone())
        .collect::<Vec<_>>();
    let before_clipboard_mode = vault.settings.clipboard_mode.clone();
    let before_clipboard_timeout = vault.settings.clipboard_timeout_secs;
    let before_clipboard_remember_choice = vault.settings.clipboard_remember_choice;

    vault.categories.sort_by_key(|category| category.sort_order);

    let mut remainder = Vec::new();
    let mut removed_ids = HashSet::new();
    for category in vault.categories.drain(..) {
        match category.id.as_str() {
            BUILTIN_LOGIN_CATEGORY_ID | BUILTIN_API_KEYS_CATEGORY_ID | BUILTIN_OTHER_CATEGORY_ID => {
                remainder.push(category);
            }
            _ => {
                if category.built_in {
                    removed_ids.insert(category.id);
                } else {
                    let mut normalized = category;
                    normalized.built_in = false;
                    remainder.push(normalized);
                }
            }
        }
    }

    let mut normalized = Vec::with_capacity(remainder.len() + defaults.len());
    for (index, builtin) in defaults.into_iter().enumerate() {
        if let Some(position) = remainder.iter().position(|category| category.id == builtin.id) {
            let mut existing = remainder.remove(position);
            existing.name = builtin.name;
            existing.emoji = builtin.emoji;
            existing.color = builtin.color;
            existing.sort_order = index as u32;
            existing.built_in = true;
            normalized.push(existing);
        } else {
            normalized.push(builtin);
        }
    }

    let base_len = normalized.len();
    for (offset, mut category) in remainder.into_iter().enumerate() {
        category.sort_order = (base_len + offset) as u32;
        category.built_in = false;
        normalized.push(category);
    }

    let known_ids = normalized
        .iter()
        .map(|category| category.id.clone())
        .collect::<HashSet<_>>();

    for entry in &mut vault.entries {
        if let Some(category_id) = entry.category_id.as_ref() {
            if removed_ids.contains(category_id) || !known_ids.contains(category_id) {
                entry.category_id = Some(BUILTIN_OTHER_CATEGORY_ID.to_string());
            }
        }
    }

    for trash_entry in &mut vault.trash {
        if let Some(category_id) = trash_entry.entry.category_id.as_ref() {
            if removed_ids.contains(category_id) || !known_ids.contains(category_id) {
                trash_entry.entry.category_id = Some(BUILTIN_OTHER_CATEGORY_ID.to_string());
            }
        }
    }

    if !is_valid_clipboard_timeout(vault.settings.clipboard_timeout_secs) {
        vault.settings.clipboard_timeout_secs = default_clipboard_timeout_secs();
    }

    normalize_entry_sort_order(&mut vault.entries);
    vault.entries.sort_by(|left, right| {
        left.category_id
            .cmp(&right.category_id)
            .then_with(|| left.sort_order.cmp(&right.sort_order))
            .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
    });

    vault.categories = normalized;

    before_categories
        != vault
            .categories
            .iter()
            .map(category_signature)
            .collect::<Vec<_>>()
        || before_entry_categories
            != vault
                .entries
                .iter()
                .map(|entry| entry.category_id.clone())
                .collect::<Vec<_>>()
        || before_trash_categories
            != vault
                .trash
                .iter()
                .map(|item| item.entry.category_id.clone())
                .collect::<Vec<_>>()
        || before_clipboard_mode != vault.settings.clipboard_mode
        || before_clipboard_timeout != vault.settings.clipboard_timeout_secs
        || before_clipboard_remember_choice != vault.settings.clipboard_remember_choice
}

fn is_valid_clipboard_timeout(timeout_secs: u32) -> bool {
    matches!(timeout_secs, 60 | 300 | 600 | 1800)
}

fn category_signature(category: &Category) -> (String, String, String, String, u32, bool) {
    (
        category.id.clone(),
        category.name.clone(),
        category.emoji.clone(),
        category.color.clone(),
        category.sort_order,
        category.built_in,
    )
}

fn normalize_entry_sort_order(entries: &mut [Entry]) {
    let mut next_order_by_category: std::collections::HashMap<Option<String>, u32> =
        std::collections::HashMap::new();

    for entry in entries.iter_mut() {
        let key = entry.category_id.clone();
        let next_order = next_order_by_category.entry(key).or_insert(0);
        if entry.sort_order < *next_order {
            entry.sort_order = *next_order;
        }
        *next_order = entry.sort_order.saturating_add(1);
    }
}

/// Data sent back to the frontend for entry listing (summary view)
#[derive(Debug, Clone, Serialize)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category_id: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub modified_at: DateTime<Utc>,
    pub sort_order: u32,
}

impl From<&Entry> for EntrySummary {
    fn from(entry: &Entry) -> Self {
        EntrySummary {
            id: entry.id.clone(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            category_id: entry.category_id.clone(),
            tags: entry.tags.clone(),
            favorite: entry.favorite,
            modified_at: entry.modified_at,
            sort_order: entry.sort_order,
        }
    }
}

/// Input data for creating/updating an entry from the frontend
#[derive(Debug, Clone, Deserialize)]
pub struct EntryInput {
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category_id: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: Vec<CustomField>,
    pub favorite: bool,
}

/// Input data for creating/updating a category
#[derive(Debug, Clone, Deserialize)]
pub struct CategoryInput {
    pub name: String,
    pub emoji: String,
    pub color: String,
}

/// Settings update from the frontend
#[derive(Debug, Clone, Deserialize)]
pub struct SettingsInput {
    pub auto_lock_minutes: Option<u32>,
    pub clipboard_mode: Option<ClipboardMode>,
    pub clipboard_timeout_secs: Option<u32>,
    pub clipboard_remember_choice: Option<bool>,
    pub language: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_categories_match_requested_builtins() {
        let categories = default_categories();
        assert_eq!(categories.len(), 3);
        assert_eq!(categories[0].id, BUILTIN_LOGIN_CATEGORY_ID);
        assert_eq!(categories[1].id, BUILTIN_API_KEYS_CATEGORY_ID);
        assert_eq!(categories[2].id, BUILTIN_OTHER_CATEGORY_ID);
        assert!(categories.iter().all(|category| category.built_in));
    }

    #[test]
    fn normalize_vault_data_reassigns_removed_builtin_entries_to_other() {
        let mut vault = VaultData::new_empty();
        vault.categories = vec![
            Category {
                id: "legacy-login".to_string(),
                name: "Login".to_string(),
                emoji: "🔑".to_string(),
                color: "#ff00aa".to_string(),
                sort_order: 0,
                built_in: true,
            },
            Category {
                id: "custom-team".to_string(),
                name: "Team".to_string(),
                emoji: "💼".to_string(),
                color: "#334455".to_string(),
                sort_order: 1,
                built_in: false,
            },
        ];
        let mut reassigned = Entry::new("Example".to_string());
        reassigned.category_id = Some("legacy-login".to_string());
        vault.entries.push(reassigned);

        let changed = normalize_vault_data(&mut vault);

        assert!(changed);
        assert_eq!(vault.categories[0].id, BUILTIN_LOGIN_CATEGORY_ID);
        assert_eq!(vault.categories[1].id, BUILTIN_API_KEYS_CATEGORY_ID);
        assert_eq!(vault.categories[2].id, BUILTIN_OTHER_CATEGORY_ID);
        assert_eq!(vault.categories[3].id, "custom-team");
        assert_eq!(
            vault.entries[0].category_id.as_deref(),
            Some(BUILTIN_OTHER_CATEGORY_ID)
        );
    }

    #[test]
    fn settings_defaults_migrate_to_timed_clipboard_mode() {
        let mut vault = VaultData::new_empty();
        vault.settings.clipboard_mode = ClipboardMode::Timed;
        vault.settings.clipboard_timeout_secs = 15;

        let changed = normalize_vault_data(&mut vault);

        assert!(changed);
        assert_eq!(vault.settings.clipboard_mode, ClipboardMode::Timed);
        assert_eq!(vault.settings.clipboard_timeout_secs, 300);
    }
}
