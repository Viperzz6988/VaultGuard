//! Security hardening for VaultGuard
//!
//! Platform-specific security measures:
//! - Core dump prevention (Linux: prctl)
//! - Memory locking (mlock to prevent swap)
//! - File permission enforcement
//! - Brute-force protection with signed persisted lockout state

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{VaultError, VaultResult};

const MACHINE_KEY_SIZE: usize = 32;
const DEFAULT_MAX_ATTEMPTS: u32 = 10;

/// Disable core dumps on Linux to prevent memory leaks to disk.
pub fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl` is invoked with the documented `PR_SET_DUMPABLE`
        // operation and scalar arguments only.
        unsafe {
            let result = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            if result != 0 {
                log::warn!("Failed to disable core dumps: prctl returned {}", result);
            }
        }
    }
}

/// Lock a memory region to prevent it from being swapped to disk.
#[allow(dead_code)]
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: The caller provides a raw pointer and length referencing a
        // valid memory region for the lifetime of the lock. The OS validates
        // page mappings and returns failure if the lock cannot be applied.
        unsafe {
            let result = libc::mlock(ptr as *const libc::c_void, len);
            if result == 0 {
                true
            } else {
                log::warn!("mlock failed (may need elevated privileges)");
                false
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Unlock a previously locked memory region.
#[allow(dead_code)]
pub fn unlock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    {
        // SAFETY: The pointer and length must reference a region previously
        // passed to `mlock`. `munlock` tolerates repeated calls by returning an
        // error we intentionally ignore because the buffer is being dropped.
        unsafe {
            let _ = libc::munlock(ptr as *const libc::c_void, len);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
    }
}

/// Set file permissions to the given mode (Unix only).
pub fn set_file_permissions(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mut perms = metadata.permissions();
            perms.set_mode(mode);
            if let Err(error) = fs::set_permissions(path, perms) {
                log::warn!("Failed to set file permissions on {:?}: {}", path, error);
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

/// Check if file permissions are secure (owner-only access on Unix).
pub fn check_file_permissions(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            (mode & 0o077) == 0
        } else {
            false
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

/// Read the last modification timestamp for a file.
pub fn file_modified_at(path: &Path) -> Option<DateTime<Utc>> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    Some(DateTime::<Utc>::from(modified))
}

/// Path used to persist brute-force throttling state.
pub fn brute_force_state_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("brute_force_state.json")
}

/// Legacy path used by older VaultGuard builds for persisted brute-force state.
pub fn legacy_brute_force_state_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("security_state.json")
}

/// Machine-local key path used to authenticate persisted brute-force state.
pub fn machine_id_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("machine_id.bin")
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LockoutReason {
    Attempts,
    TamperMissingState,
    TamperInvalidHmac,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyPersistedBruteForceState {
    failed_attempts: u32,
    max_attempts: u32,
    lockout_tier: u8,
    last_failed_at: Option<DateTime<Utc>>,
    lockout_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedBruteForceState {
    failed_attempts: u32,
    max_attempts: u32,
    lockout_tier: u8,
    current_cycle_failures: u32,
    last_failed_at: Option<DateTime<Utc>>,
    lockout_until: Option<DateTime<Utc>>,
    active_backoff_until: Option<DateTime<Utc>>,
    lockout_reason: LockoutReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedBruteForceState {
    failed_attempts: u32,
    max_attempts: u32,
    lockout_tier: u8,
    current_cycle_failures: u32,
    last_failed_at: Option<DateTime<Utc>>,
    lockout_until: Option<DateTime<Utc>>,
    active_backoff_until: Option<DateTime<Utc>>,
    lockout_reason: LockoutReason,
    hmac: String,
}

impl From<UnsignedBruteForceState> for SignedBruteForceState {
    fn from(value: UnsignedBruteForceState) -> Self {
        SignedBruteForceState {
            failed_attempts: value.failed_attempts,
            max_attempts: value.max_attempts,
            lockout_tier: value.lockout_tier,
            current_cycle_failures: value.current_cycle_failures,
            last_failed_at: value.last_failed_at,
            lockout_until: value.lockout_until,
            active_backoff_until: value.active_backoff_until,
            lockout_reason: value.lockout_reason,
            hmac: String::new(),
        }
    }
}

impl From<&SignedBruteForceState> for UnsignedBruteForceState {
    fn from(value: &SignedBruteForceState) -> Self {
        UnsignedBruteForceState {
            failed_attempts: value.failed_attempts,
            max_attempts: value.max_attempts,
            lockout_tier: value.lockout_tier,
            current_cycle_failures: value.current_cycle_failures,
            last_failed_at: value.last_failed_at,
            lockout_until: value.lockout_until,
            active_backoff_until: value.active_backoff_until,
            lockout_reason: value.lockout_reason,
        }
    }
}

/// Brute-force protection with exponential backoff and tamper-evident persisted state.
#[derive(Debug)]
pub struct BruteForceProtection {
    pub failed_attempts: u32,
    pub max_attempts: u32,
    pub lockout_tier: u8,
    pub current_cycle_failures: u32,
    last_failed_at: Option<DateTime<Utc>>,
    lockout_until: Option<DateTime<Utc>>,
    active_backoff_until: Option<DateTime<Utc>>,
    lockout_reason: LockoutReason,
    state_path: PathBuf,
    machine_path: PathBuf,
    legacy_state_path: PathBuf,
}

impl BruteForceProtection {
    pub fn load(state_path: PathBuf) -> Self {
        let machine_path = machine_id_path(&state_path);
        let legacy_state_path = legacy_brute_force_state_path(&state_path);

        match Self::load_inner(state_path.clone(), machine_path.clone(), legacy_state_path.clone()) {
            Ok(mut protection) => {
                if let Err(error) = protection.refresh() {
                    log::warn!("Failed to refresh brute-force state: {}", error);
                }
                protection
            }
            Err(error) => {
                log::warn!("Failed to load brute-force state: {}", error);
                Self::fresh(state_path, machine_path, legacy_state_path)
            }
        }
    }

    fn load_inner(
        state_path: PathBuf,
        machine_path: PathBuf,
        legacy_state_path: PathBuf,
    ) -> VaultResult<Self> {
        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent)?;
            set_file_permissions(parent, 0o700);
        }

        if state_path.exists() {
            let machine_key = load_machine_key(&machine_path)
                .ok_or_else(|| VaultError::IntegrityViolation("Missing machine identity".into()))?;
            let content = fs::read_to_string(&state_path)?;
            let signed: SignedBruteForceState = serde_json::from_str(&content)
                .map_err(|_| VaultError::IntegrityViolation("Invalid lockout state file".into()))?;
            let unsigned = UnsignedBruteForceState::from(&signed);
            let expected_hmac = compute_state_hmac(&unsigned, &machine_key)?;
            if !constant_time_hex_eq(&signed.hmac, &expected_hmac) {
                let mut tampered =
                    Self::fresh(state_path, machine_path, legacy_state_path);
                tampered.apply_tamper_lockout(LockoutReason::TamperInvalidHmac, 3);
                tampered.persist()?;
                return Ok(tampered);
            }

            return Ok(Self {
                failed_attempts: unsigned.failed_attempts,
                max_attempts: unsigned.max_attempts.max(DEFAULT_MAX_ATTEMPTS),
                lockout_tier: unsigned.lockout_tier.min(3),
                current_cycle_failures: unsigned.current_cycle_failures.min(DEFAULT_MAX_ATTEMPTS),
                last_failed_at: unsigned.last_failed_at,
                lockout_until: unsigned.lockout_until,
                active_backoff_until: unsigned.active_backoff_until,
                lockout_reason: unsigned.lockout_reason,
                state_path,
                machine_path,
                legacy_state_path,
            });
        }

        if legacy_state_path.exists() {
            let content = fs::read_to_string(&legacy_state_path)?;
            let legacy: LegacyPersistedBruteForceState = serde_json::from_str(&content)?;
            let protection = Self {
                failed_attempts: legacy.failed_attempts,
                max_attempts: legacy.max_attempts.max(DEFAULT_MAX_ATTEMPTS),
                lockout_tier: legacy.lockout_tier.min(3),
                current_cycle_failures: legacy.failed_attempts.min(DEFAULT_MAX_ATTEMPTS),
                last_failed_at: legacy.last_failed_at,
                lockout_until: legacy.lockout_until,
                active_backoff_until: None,
                lockout_reason: LockoutReason::Attempts,
                state_path,
                machine_path,
                legacy_state_path,
            };
            protection.persist()?;
            let _ = fs::remove_file(&protection.legacy_state_path);
            return Ok(protection);
        }

        if machine_path.exists() {
            let mut tampered = Self::fresh(state_path, machine_path, legacy_state_path);
            tampered.apply_tamper_lockout(LockoutReason::TamperMissingState, 2);
            tampered.persist()?;
            return Ok(tampered);
        }

        let protection = Self::fresh(state_path, machine_path, legacy_state_path);
        protection.persist()?;
        Ok(protection)
    }

    fn fresh(state_path: PathBuf, machine_path: PathBuf, legacy_state_path: PathBuf) -> Self {
        BruteForceProtection {
            failed_attempts: 0,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            lockout_tier: 0,
            current_cycle_failures: 0,
            last_failed_at: None,
            lockout_until: None,
            active_backoff_until: None,
            lockout_reason: LockoutReason::Attempts,
            state_path,
            machine_path,
            legacy_state_path,
        }
    }

    fn unsigned_state(&self) -> UnsignedBruteForceState {
        UnsignedBruteForceState {
            failed_attempts: self.failed_attempts,
            max_attempts: self.max_attempts,
            lockout_tier: self.lockout_tier,
            current_cycle_failures: self.current_cycle_failures,
            last_failed_at: self.last_failed_at,
            lockout_until: self.lockout_until,
            active_backoff_until: self.active_backoff_until,
            lockout_reason: self.lockout_reason,
        }
    }

    fn apply_tamper_lockout(&mut self, reason: LockoutReason, tier: u8) {
        self.failed_attempts = self.max_attempts;
        self.current_cycle_failures = self.max_attempts;
        self.lockout_tier = tier.min(3);
        self.last_failed_at = Some(Utc::now());
        self.active_backoff_until = None;
        self.lockout_until = Some(Utc::now() + lockout_duration_for_tier(self.lockout_tier));
        self.lockout_reason = reason;
    }

    pub fn refresh(&mut self) -> VaultResult<()> {
        let now = Utc::now();
        let mut changed = false;

        if let Some(lockout_until) = self.lockout_until {
            if now >= lockout_until {
                self.failed_attempts = 0;
                self.current_cycle_failures = 0;
                self.last_failed_at = None;
                self.lockout_until = None;
                self.active_backoff_until = None;
                self.lockout_reason = LockoutReason::Attempts;
                changed = true;
            }
        }

        if let Some(backoff_until) = self.active_backoff_until {
            if now >= backoff_until {
                self.active_backoff_until = None;
                changed = true;
            }
        }

        if changed {
            self.persist()?;
        }

        Ok(())
    }

    fn persist(&self) -> VaultResult<()> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent)?;
            set_file_permissions(parent, 0o700);
        }

        let machine_key = ensure_machine_key(&self.machine_path)?;
        let unsigned = self.unsigned_state();
        let mut signed = SignedBruteForceState::from(unsigned.clone());
        signed.hmac = compute_state_hmac(&unsigned, &machine_key)?;

        let json = serde_json::to_string_pretty(&signed)
            .map_err(|e| VaultError::Serialization(format!("Failed to serialize brute-force state: {}", e)))?;
        atomic_write(&self.state_path, json.as_bytes())?;
        set_file_permissions(&self.state_path, 0o600);
        Ok(())
    }

    pub fn is_locked_out(&self) -> bool {
        self.lockout_until
            .map(|lockout_until| Utc::now() < lockout_until)
            .unwrap_or(false)
    }

    pub fn lockout_remaining_secs(&self) -> u64 {
        self.lockout_until
            .map(remaining_secs_until)
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub fn get_delay(&self) -> Duration {
        self.must_wait().unwrap_or_else(|| Duration::from_secs(0))
    }

    pub fn must_wait(&self) -> Option<Duration> {
        if self.is_locked_out() {
            return Some(Duration::from_secs(self.lockout_remaining_secs()));
        }

        if let Some(backoff_until) = self.active_backoff_until {
            if Utc::now() < backoff_until {
                return Some(Duration::from_secs(remaining_secs_until(backoff_until)));
            }
        }

        None
    }

    pub fn record_failure(&mut self) -> VaultResult<()> {
        let now = Utc::now();
        self.failed_attempts = self.failed_attempts.saturating_add(1).min(self.max_attempts);
        self.current_cycle_failures = self
            .current_cycle_failures
            .saturating_add(1)
            .min(self.max_attempts);
        self.last_failed_at = Some(now);
        self.lockout_reason = LockoutReason::Attempts;

        if self.current_cycle_failures >= self.max_attempts {
            self.lockout_tier = self.lockout_tier.saturating_add(1).min(3);
            self.lockout_until = Some(now + lockout_duration_for_tier(self.lockout_tier));
            self.active_backoff_until = None;
            self.failed_attempts = self.max_attempts;
            self.current_cycle_failures = self.max_attempts;
        } else {
            let delay_secs = (1u64 << (self.current_cycle_failures - 1).min(6)).min(60);
            self.active_backoff_until = Some(
                now + chrono::Duration::seconds(i64::try_from(delay_secs).unwrap_or(60)),
            );
        }

        self.persist()
    }

    pub fn record_successful_unlock(&mut self) -> VaultResult<()> {
        self.failed_attempts = 0;
        self.current_cycle_failures = 0;
        self.last_failed_at = None;
        self.lockout_until = None;
        self.active_backoff_until = None;
        self.lockout_reason = LockoutReason::Attempts;
        self.persist()
    }

    pub fn record_success(&mut self) -> VaultResult<()> {
        self.record_successful_unlock()
    }

    pub fn remaining_attempts(&self) -> u32 {
        self.max_attempts.saturating_sub(self.current_cycle_failures)
    }

    pub fn get_status(&self) -> BruteForceStatus {
        BruteForceStatus {
            failed_attempts: self.failed_attempts,
            remaining_attempts: self.remaining_attempts(),
            is_locked_out: self.is_locked_out(),
            lockout_remaining_secs: self.lockout_remaining_secs(),
            delay_secs: self.must_wait().map(|wait| wait.as_secs()).unwrap_or(0),
            lockout_tier: self.lockout_tier,
            next_lockout_tier: self.lockout_tier.saturating_add(1).min(3),
            lockout_reason: match self.lockout_reason {
                LockoutReason::Attempts => "attempts".to_string(),
                LockoutReason::TamperMissingState => "tamper_missing_state".to_string(),
                LockoutReason::TamperInvalidHmac => "tamper_invalid_hmac".to_string(),
            },
        }
    }
}

fn remaining_secs_until(target: DateTime<Utc>) -> u64 {
    let millis = target
        .signed_duration_since(Utc::now())
        .num_milliseconds()
        .max(0);
    ((millis + 999) / 1000) as u64
}

fn lockout_duration_for_tier(tier: u8) -> chrono::Duration {
    match tier {
        1 => chrono::Duration::hours(12),
        2 => chrono::Duration::hours(24),
        _ => chrono::Duration::weeks(1),
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("tmp")
    ));
    fs::write(&tmp_path, bytes)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn ensure_machine_key(machine_path: &Path) -> VaultResult<[u8; MACHINE_KEY_SIZE]> {
    if let Some(existing) = load_machine_key(machine_path) {
        return Ok(existing);
    }

    if let Some(parent) = machine_path.parent() {
        fs::create_dir_all(parent)?;
        set_file_permissions(parent, 0o700);
    }

    let mut key = [0u8; MACHINE_KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    atomic_write(machine_path, &key)?;
    set_file_permissions(machine_path, 0o600);
    Ok(key)
}

fn load_machine_key(machine_path: &Path) -> Option<[u8; MACHINE_KEY_SIZE]> {
    let bytes = fs::read(machine_path).ok()?;
    if bytes.len() != MACHINE_KEY_SIZE {
        return None;
    }
    let mut key = [0u8; MACHINE_KEY_SIZE];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn compute_state_hmac(
    unsigned: &UnsignedBruteForceState,
    machine_key: &[u8; MACHINE_KEY_SIZE],
) -> VaultResult<String> {
    let json = serde_json::to_vec(unsigned)
        .map_err(|e| VaultError::Serialization(format!("Failed to serialize brute-force state: {}", e)))?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(machine_key)
        .map_err(|e| VaultError::Crypto(format!("Failed to initialize brute-force HMAC: {}", e)))?;
    mac.update(&json);
    let result = mac.finalize().into_bytes();
    Ok(hex_encode(&result))
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq;
    left.as_bytes().ct_eq(right.as_bytes()).into()
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

/// Brute force status sent to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct BruteForceStatus {
    pub failed_attempts: u32,
    pub remaining_attempts: u32,
    pub is_locked_out: bool,
    pub lockout_remaining_secs: u64,
    pub delay_secs: u64,
    pub lockout_tier: u8,
    pub next_lockout_tier: u8,
    pub lockout_reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(name: &str) -> PathBuf {
        let unique = uuid::Uuid::new_v4().to_string();
        let dir = std::env::temp_dir().join(format!("vaultguard-security-{}-{}", name, unique));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn state_path(name: &str) -> PathBuf {
        unique_dir(name).join("brute_force_state.json")
    }

    #[test]
    fn failed_attempts_escalate_delay() {
        let path = state_path("delay");
        let mut protection = BruteForceProtection::load(path.clone());

        protection
            .record_failure()
            .expect("test should record first failed attempt");
        assert_eq!(protection.get_delay().as_secs(), 1);

        protection
            .record_failure()
            .expect("test should record second failed attempt");
        assert_eq!(protection.get_delay().as_secs(), 2);

        protection
            .record_failure()
            .expect("test should record third failed attempt");
        assert_eq!(protection.get_delay().as_secs(), 4);
    }

    #[test]
    fn tenth_failure_triggers_lockout() {
        let path = state_path("lockout");
        let mut protection = BruteForceProtection::load(path.clone());

        for _ in 0..10 {
            protection
                .record_failure()
                .expect("test should record lockout failures");
        }

        assert!(protection.is_locked_out());
        assert_eq!(protection.remaining_attempts(), 0);
        assert_eq!(protection.lockout_tier, 1);
        assert_eq!(protection.get_status().lockout_reason, "attempts");
    }

    #[test]
    fn state_persists_between_instances() {
        let path = state_path("persist");
        let mut first = BruteForceProtection::load(path.clone());
        first
            .record_failure()
            .expect("test should record first persisted failure");
        first
            .record_failure()
            .expect("test should record second persisted failure");

        let second = BruteForceProtection::load(path.clone());
        assert_eq!(second.failed_attempts, 2);
        assert_eq!(second.get_delay().as_secs(), 2);
        assert_eq!(second.lockout_tier, 0);
    }

    #[test]
    fn lockout_tier_escalates_across_cycles() {
        let path = state_path("tier");
        let mut protection = BruteForceProtection::load(path.clone());

        for expected_tier in [1u8, 2u8, 3u8] {
            for _ in 0..10 {
                protection
                    .record_failure()
                    .expect("test should record failures across lockout tiers");
            }
            assert_eq!(protection.lockout_tier, expected_tier);
            protection.lockout_until = Some(Utc::now() - chrono::Duration::seconds(1));
            protection
                .refresh()
                .expect("test should refresh expired lockout");
        }
    }

    #[test]
    fn successful_unlock_resets_attempts_but_not_tier() {
        let path = state_path("success-reset");
        let mut protection = BruteForceProtection::load(path.clone());
        protection.lockout_tier = 2;
        protection
            .record_failure()
            .expect("test should record first reset failure");
        protection
            .record_failure()
            .expect("test should record second reset failure");

        protection
            .record_successful_unlock()
            .expect("test should record successful unlock");

        assert_eq!(protection.failed_attempts, 0);
        assert_eq!(protection.current_cycle_failures, 0);
        assert_eq!(protection.lockout_tier, 2);
        assert_eq!(protection.get_delay().as_secs(), 0);
    }

    #[test]
    fn missing_state_with_existing_machine_identity_triggers_tamper_lockout() {
        let path = state_path("tamper-missing");
        let machine_path = path
            .parent()
            .expect("test state path should have a parent directory")
            .join("machine_id.bin");
        ensure_machine_key(&machine_path).expect("test should create machine identity");

        let protection = BruteForceProtection::load(path.clone());

        assert!(protection.is_locked_out());
        assert_eq!(protection.lockout_tier, 2);
        assert_eq!(protection.get_status().lockout_reason, "tamper_missing_state");
    }

    #[test]
    fn invalid_hmac_triggers_maximum_tamper_lockout() {
        let path = state_path("tamper-hmac");
        let mut protection = BruteForceProtection::load(path.clone());
        protection
            .record_failure()
            .expect("test should record failure before tamper");

        let mut content = fs::read_to_string(&path).expect("test should read signed state");
        content = content.replace("\"hmac\":", "\"hmac\":\"broken\", \"hmac_original\":");
        fs::write(&path, content).expect("test should write tampered state");

        let protection = BruteForceProtection::load(path.clone());

        assert!(protection.is_locked_out());
        assert_eq!(protection.lockout_tier, 3);
        assert_eq!(protection.get_status().lockout_reason, "tamper_invalid_hmac");
    }

    #[test]
    fn legacy_state_is_migrated_to_signed_format() {
        let path = state_path("legacy");
        let legacy_path = path
            .parent()
            .expect("test state path should have a parent directory")
            .join("security_state.json");
        let legacy = LegacyPersistedBruteForceState {
            failed_attempts: 3,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            lockout_tier: 1,
            last_failed_at: Some(Utc::now()),
            lockout_until: None,
        };
        fs::write(
            &legacy_path,
            serde_json::to_string(&legacy).expect("test should serialize legacy state"),
        )
        .expect("test should write legacy state");

        let protection = BruteForceProtection::load(path.clone());

        assert_eq!(protection.failed_attempts, 3);
        assert!(path.exists());
        assert!(!legacy_path.exists());
    }
}
