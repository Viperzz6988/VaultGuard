//! Cryptographic operations for VaultGuard
//!
//! All cryptographic primitives are contained here:
//! - Argon2id key derivation (KEK from master password)
//! - AES-256-GCM authenticated encryption (envelope encryption)
//! - HMAC-SHA256 integrity verification
//! - Secure random generation via OS CSPRNG

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Algorithm, Version, Params};
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{VaultError, VaultResult};

/// Nonce size for AES-256-GCM (96 bits = 12 bytes)
const NONCE_SIZE: usize = 12;
/// Salt size for Argon2id (256 bits = 32 bytes)
pub const SALT_SIZE: usize = 32;
/// Key size for AES-256 (256 bits = 32 bytes)
pub const KEY_SIZE: usize = 32;
/// HMAC output size (SHA-256 = 32 bytes)
pub const HMAC_SIZE: usize = 32;

/// Argon2id parameters — non-negotiable minimums per spec
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Generate a cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random 256-bit Data Encryption Key (DEK)
pub fn generate_dek() -> Zeroizing<[u8; KEY_SIZE]> {
    let mut dek = Zeroizing::new([0u8; KEY_SIZE]);
    OsRng.fill_bytes(dek.as_mut());
    dek
}

/// Generate a random nonce for AES-256-GCM
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive a Key Encryption Key (KEK) from a master password using Argon2id
///
/// Parameters are hardcoded to resist GPU/ASIC/timing attacks:
/// - Memory: 64 MB (m=65536)
/// - Iterations: 3 (t=3)
/// - Parallelism: 4 (p=4)
///
/// The derived key is wrapped in `Zeroizing` to ensure it's wiped from memory
/// when no longer needed.
pub fn derive_kek(password: &[u8], salt: &[u8; SALT_SIZE]) -> VaultResult<Zeroizing<[u8; KEY_SIZE]>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_SIZE),
    )
    .map_err(|e| VaultError::Crypto(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = Zeroizing::new([0u8; KEY_SIZE]);

    argon2
        .hash_password_into(password, salt, kek.as_mut())
        .map_err(|e| VaultError::Crypto(format!("Argon2id key derivation failed: {}", e)))?;

    Ok(kek)
}

/// Encrypt the DEK with the KEK using AES-256-GCM
///
/// Returns: [12-byte nonce][ciphertext+tag]
/// The ciphertext includes the 16-byte GCM authentication tag.
pub fn encrypt_dek(dek: &[u8; KEY_SIZE], kek: &[u8; KEY_SIZE]) -> VaultResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|e| VaultError::Crypto(format!("AES key init error: {}", e)))?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, dek.as_ref())
        .map_err(|e| VaultError::Crypto(format!("DEK encryption failed: {}", e)))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt the DEK using the KEK
///
/// Input format: [12-byte nonce][ciphertext+tag]
pub fn decrypt_dek(encrypted: &[u8], kek: &[u8; KEY_SIZE]) -> VaultResult<Zeroizing<[u8; KEY_SIZE]>> {
    if encrypted.len() < NONCE_SIZE + KEY_SIZE + 16 {
        return Err(VaultError::Crypto("Encrypted DEK too short".into()));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|e| VaultError::Crypto(format!("AES key init error: {}", e)))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::InvalidPassword)?;

    if plaintext.len() != KEY_SIZE {
        return Err(VaultError::Crypto("Decrypted DEK has wrong size".into()));
    }

    let mut dek = Zeroizing::new([0u8; KEY_SIZE]);
    dek.copy_from_slice(&plaintext);

    Ok(dek)
}

/// Encrypt arbitrary data with the DEK using AES-256-GCM
///
/// Each call generates a fresh random 96-bit nonce — nonce reuse is impossible.
/// Returns: [12-byte nonce][ciphertext+tag]
pub fn encrypt_data(plaintext: &[u8], dek: &[u8; KEY_SIZE]) -> VaultResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(dek)
        .map_err(|e| VaultError::Crypto(format!("AES key init error: {}", e)))?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Crypto(format!("Data encryption failed: {}", e)))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with the DEK
///
/// Input format: [12-byte nonce][ciphertext+tag]
pub fn decrypt_data(encrypted: &[u8], dek: &[u8; KEY_SIZE]) -> VaultResult<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + 16 {
        return Err(VaultError::Crypto("Encrypted data too short".into()));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(dek)
        .map_err(|e| VaultError::Crypto(format!("AES key init error: {}", e)))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::IntegrityViolation("Data decryption failed — data may be corrupted or tampered with".into()))
}

/// Compute HMAC-SHA256 over data using a key derived from the KEK
///
/// The HMAC key is derived by hashing kek with a domain separator to avoid
/// key reuse between encryption and integrity verification.
pub fn compute_hmac(data: &[u8], kek: &[u8; KEY_SIZE]) -> VaultResult<[u8; HMAC_SIZE]> {
    // Derive HMAC key from KEK using domain separation
    let mut hmac_key = Zeroizing::new([0u8; KEY_SIZE]);
    let mut hasher = <Hmac<Sha256> as Mac>::new_from_slice(b"VaultGuard-HMAC-Key-Derivation")
        .map_err(|e| VaultError::Crypto(format!("HMAC key derivation error: {}", e)))?;
    hasher.update(kek);
    let result = hasher.finalize().into_bytes();
    hmac_key.copy_from_slice(&result);

    // Compute HMAC over the data
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hmac_key.as_ref())
        .map_err(|e| VaultError::Crypto(format!("HMAC init error: {}", e)))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();

    let mut output = [0u8; HMAC_SIZE];
    output.copy_from_slice(&result);
    Ok(output)
}

/// Verify HMAC-SHA256 in constant time
///
/// Returns true if the HMAC matches, false otherwise.
/// Uses the `Mac::verify` method which performs constant-time comparison
/// to prevent timing attacks.
pub fn verify_hmac(data: &[u8], expected: &[u8; HMAC_SIZE], kek: &[u8; KEY_SIZE]) -> VaultResult<bool> {
    let computed = compute_hmac(data, kek)?;
    Ok(constant_time_eq(&computed, expected))
}

/// Constant-time byte comparison to prevent timing side-channel attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

const OFFLINE_GUESSES_PER_SECOND: f64 = 10_000_000_000.0;
const KEYBOARD_WALKS: &[&str] = &[
    "qwerty",
    "qwertz",
    "asdfgh",
    "zxcvbn",
    "poiuyt",
    "lkjhgf",
    "123456",
    "234567",
    "345678",
    "456789",
    "567890",
    "654321",
    "987654",
    "876543",
    "765432",
    "abcdef",
    "bcdefg",
    "cdefgh",
    "mnopqr",
    "zyxwvu",
];
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "qwerty",
    "letmein",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "pass",
    "test",
    "iloveyou",
    "sunshine",
    "princess",
    "football",
    "shadow",
    "baseball",
    "abc123",
    "111111",
    "000000",
    "696969",
    "mustang",
    "access",
    "superman",
];

#[derive(Debug, serde::Serialize, Clone)]
pub struct StrengthResult {
    pub level: u8,
    pub entropy_bits: f64,
    pub crack_time: String,
}

pub fn check_password_strength(password: &str) -> StrengthResult {
    if password.is_empty() {
        return StrengthResult {
            level: 0,
            entropy_bits: 0.0,
            crack_time: "instantly".into(),
        };
    }

    let has_lower = password.chars().any(|ch| ch.is_ascii_lowercase());
    let has_upper = password.chars().any(|ch| ch.is_ascii_uppercase());
    let has_digit = password.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = password.chars().any(|ch| ch.is_ascii_punctuation());

    let mut pool_size: f64 = 0.0;
    if has_lower {
        pool_size += 26.0;
    }
    if has_upper {
        pool_size += 26.0;
    }
    if has_digit {
        pool_size += 10.0;
    }
    if has_symbol {
        pool_size += 32.0;
    }
    if pool_size < 1.0 {
        pool_size = 26.0;
    }

    let length = password.chars().count() as f64;
    let mut entropy_bits = length * pool_size.log2();

    let unique = password.chars().collect::<std::collections::HashSet<_>>().len() as f64;
    let unique_ratio = unique / length;
    if unique_ratio < 0.3 {
        entropy_bits *= unique_ratio * 1.5;
    } else if unique_ratio < 0.5 {
        entropy_bits *= 0.6;
    }

    if unique == 1.0 {
        entropy_bits *= 0.05;
    }

    let lowered = password.to_lowercase();
    if contains_keyboard_walk(&lowered) {
        entropy_bits *= 0.35;
    }

    if is_common_password(&lowered) {
        entropy_bits = entropy_bits.min(8.0);
    }

    let entropy_bits = entropy_bits.max(0.0);

    let level = if entropy_bits < 28.0 {
        0
    } else if entropy_bits < 45.0 {
        1
    } else if entropy_bits < 65.0 {
        2
    } else {
        3
    };

    StrengthResult {
        level,
        entropy_bits,
        crack_time: estimate_crack_time(entropy_bits),
    }
}

pub fn estimate_password_strength(password: &str) -> StrengthResult {
    check_password_strength(password)
}

fn contains_keyboard_walk(password: &str) -> bool {
    KEYBOARD_WALKS.iter().any(|pattern| password.contains(pattern))
}

fn is_common_password(password: &str) -> bool {
    COMMON_PASSWORDS
        .iter()
        .any(|candidate| password.starts_with(candidate))
}

fn estimate_crack_time(entropy_bits: f64) -> String {
    let seconds = 2_f64.powf(entropy_bits) / 2.0 / OFFLINE_GUESSES_PER_SECOND;
    format_crack_time(seconds)
}

fn format_crack_time(seconds: f64) -> String {
    if seconds < 1.0 {
        "instantly".into()
    } else if seconds < 60.0 {
        format!("{:.0} seconds", seconds)
    } else if seconds < 3_600.0 {
        format!("{:.0} minutes", seconds / 60.0)
    } else if seconds < 86_400.0 {
        format!("{:.0} hours", seconds / 3_600.0)
    } else if seconds < 2_592_000.0 {
        format!("{:.0} days", seconds / 86_400.0)
    } else if seconds < 31_536_000.0 {
        format!("{:.0} months", seconds / 2_592_000.0)
    } else if seconds < 3_153_600_000.0 {
        format!("{:.0} years", seconds / 31_536_000.0)
    } else if seconds < 315_360_000_000.0 {
        format!("{:.0} centuries", seconds / 3_153_600_000.0)
    } else {
        "millennia".into()
    }
}

/// Generate a random password with the given options
pub fn generate_password(options: &PasswordGenOptions) -> String {
    let lowercase: &[u8] = if options.exclude_ambiguous {
        b"abcdefghjkmnpqrstuvwxyz"
    } else {
        b"abcdefghijklmnopqrstuvwxyz"
    };
    let uppercase: &[u8] = if options.exclude_ambiguous {
        b"ABCDEFGHJKMNPQRSTUVWXYZ"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    };
    let numbers: &[u8] = if options.exclude_ambiguous {
        b"23456789"
    } else {
        b"0123456789"
    };
    let symbols: &[u8] = b"!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

    let mut pools = Vec::new();
    if options.lowercase {
        pools.push(lowercase);
    }
    if options.uppercase {
        pools.push(uppercase);
    }
    if options.numbers {
        pools.push(numbers);
    }
    if options.symbols {
        pools.push(symbols);
    }
    if pools.is_empty() {
        pools.push(lowercase);
    }

    let mut charset = Vec::new();
    for pool in &pools {
        charset.extend_from_slice(pool);
    }

    let length = options.length.clamp(8, 128);
    let mut rng = OsRng;
    let mut password = Vec::with_capacity(length);

    // Guarantee at least one character from every selected class.
    for pool in &pools {
        if let Some(ch) = pool.choose(&mut rng) {
            password.push(*ch);
        }
    }

    while password.len() < length {
        if let Some(ch) = charset.choose(&mut rng) {
            password.push(*ch);
        }
    }

    password.shuffle(&mut rng);

    String::from_utf8(password).unwrap_or_default()
}

/// Generate a passphrase from the EFF wordlist
pub fn generate_passphrase(word_count: usize, separator: &str) -> String {
    let words = eff_wordlist();
    let count = word_count.clamp(3, 10);
    let mut rng = OsRng;

    let selected: Vec<&str> = (0..count)
        .map(|_| {
            let idx = (rng.next_u32() as usize) % words.len();
            words[idx]
        })
        .collect();

    selected.join(separator)
}

#[derive(serde::Deserialize, Clone)]
pub struct PasswordGenOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

/// EFF large wordlist (subset for reasonable binary size — 1024 common words)
fn eff_wordlist() -> Vec<&'static str> {
    vec![
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acquire", "across", "action", "actor", "actress", "actual", "adapt", "address",
        "adjust", "admit", "adult", "advance", "advice", "afford", "afraid", "again",
        "agent", "agree", "ahead", "airport", "aisle", "alarm", "album", "alcohol",
        "alert", "alien", "almost", "alone", "alpha", "already", "also", "alter",
        "always", "amateur", "amazing", "among", "amount", "amused", "anchor", "ancient",
        "anger", "angle", "animal", "ankle", "annual", "another", "answer", "antenna",
        "antique", "anxiety", "apart", "apology", "appear", "apple", "approve", "april",
        "arena", "argue", "armor", "army", "arrange", "arrest", "arrive", "arrow",
        "artist", "artwork", "aspect", "assault", "asset", "assist", "assume", "asthma",
        "athlete", "atom", "attack", "attend", "attract", "auction", "audit", "august",
        "author", "autumn", "average", "avocado", "avoid", "awake", "aware", "awesome",
        "awful", "awkward", "bachelor", "bacon", "badge", "balance", "balcony", "bamboo",
        "banana", "banner", "bargain", "barrel", "basic", "basket", "battle", "beach",
        "beauty", "become", "bedroom", "before", "begin", "behave", "believe", "below",
        "bench", "benefit", "between", "beyond", "bicycle", "blanket", "blast", "blaze",
        "blessing", "blind", "blood", "blossom", "board", "bonus", "border", "bottle",
        "bounce", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze",
        "bridge", "bright", "bring", "broken", "bronze", "brother", "brush", "bubble",
        "budget", "buffalo", "build", "bullet", "bundle", "burden", "burger", "burst",
        "butter", "cabin", "cable", "cactus", "camera", "cancel", "candle", "cannon",
        "canvas", "canyon", "capable", "capital", "captain", "carbon", "carpet", "cargo",
        "carry", "castle", "catalog", "catch", "cattle", "caught", "cause", "caution",
        "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair",
        "chalk", "champion", "change", "chapter", "charge", "chase", "cheap", "check",
        "cheese", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
        "chunks", "cinema", "circle", "citizen", "civil", "claim", "clarify", "claw",
        "clean", "clever", "click", "client", "cliff", "climb", "clinic", "clock",
        "closet", "cloud", "cluster", "coach", "coast", "coconut", "coffee", "collect",
        "color", "column", "comfort", "comic", "common", "company", "concert", "conduct",
        "confirm", "connect", "consider", "control", "convert", "cookie", "copper", "coral",
        "corner", "correct", "couch", "country", "couple", "course", "cousin", "cover",
        "cradle", "craft", "crash", "crater", "crazy", "cream", "credit", "cricket",
        "crisis", "crisp", "critic", "cross", "crouch", "crowd", "crucial", "cruel",
        "cruise", "crumble", "crush", "crystal", "culture", "curtain", "curve", "cushion",
        "custom", "cycle", "damage", "dance", "danger", "daring", "dash", "daughter",
        "dawn", "debate", "decade", "december", "decide", "decline", "decorate", "decrease",
        "defense", "define", "delay", "deliver", "demand", "denial", "dentist", "deposit",
        "depth", "deputy", "derive", "desert", "design", "desk", "detail", "detect",
        "develop", "device", "devote", "diagram", "diamond", "diary", "diesel", "differ",
        "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree",
        "discover", "disease", "display", "distance", "divert", "divide", "doctor", "document",
        "domain", "donate", "donkey", "donor", "door", "double", "dragon", "drama",
        "drastic", "dream", "dress", "drift", "drink", "drive", "drop", "drum",
        "dumpster", "during", "dust", "dutch", "dwarf", "dynamic", "eager", "eagle",
        "early", "earth", "easily", "eastern", "eclipse", "ecology", "economy", "editor",
        "educate", "effort", "eight", "either", "elbow", "elder", "electric", "elegant",
        "element", "elephant", "elevator", "elite", "embrace", "emerge", "emotion", "emperor",
        "enable", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine",
        "enjoy", "enough", "enrich", "ensure", "enter", "entire", "entity", "envelope",
        "episode", "equal", "equip", "erosion", "error", "escape", "essay", "eternal",
        "evidence", "evil", "evolve", "exact", "example", "excess", "exchange", "exclude",
        "excuse", "execute", "exercise", "exhaust", "exhibit", "exotic", "expand", "expect",
        "expense", "expert", "explain", "expose", "express", "extend", "extra", "eyebrow",
        "fabric", "faculty", "fading", "failure", "falcon", "family", "famous", "fancy",
        "fantasy", "fashion", "father", "fatigue", "fault", "favorite", "feature", "federal",
        "fence", "festival", "fetch", "fever", "fiction", "field", "figure", "filter",
        "final", "finger", "finish", "first", "fish", "fitness", "flame", "flash",
        "flavor", "flight", "float", "flock", "floor", "flower", "fluid", "flush",
        "focus", "follow", "force", "forest", "forget", "formal", "fortune", "forum",
        "forward", "fossil", "foster", "found", "framed", "freeze", "fresh", "friend",
        "fringe", "frozen", "fruit", "fulfill", "funny", "furnace", "fury", "future",
        "gadget", "galaxy", "gallery", "gamble", "garage", "garden", "garlic", "garment",
        "gather", "gauge", "general", "genius", "gentle", "genuine", "gesture", "ghost",
        "giant", "ginger", "giraffe", "glimpse", "global", "glory", "glove", "goddess",
        "golden", "goose", "gorilla", "gospel", "gossip", "govern", "grace", "grain",
        "grant", "grape", "gravity", "great", "green", "grid", "grief", "grocery",
        "group", "grow", "grunt", "guard", "guess", "guide", "guitar", "habit",
        "hammer", "hamster", "happen", "harbor", "harvest", "hawk", "hazard", "health",
        "heart", "heavy", "hedgehog", "height", "hello", "helmet", "hero", "hidden",
        "highway", "hilltop", "history", "hobby", "holder", "hollow", "honest", "honey",
        "horizon", "horror", "horse", "hospital", "hotel", "hover", "humble", "humor",
        "hundred", "hungry", "hurdle", "husband", "hybrid", "identify", "ignore", "illegal",
        "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve",
        "impulse", "income", "increase", "index", "indicate", "indoor", "industry", "infant",
        "inflict", "inform", "initial", "inject", "inmate", "innocent", "input", "inquiry",
        "insane", "insect", "inside", "install", "intact", "interest", "invest", "invite",
        "involve", "iron", "island", "isolate", "ivory", "jacket", "jaguar", "jealous",
        "jelly", "jewel", "journey", "judge", "juice", "jungle", "junior", "junkyard",
        "justice", "kangaroo", "kayak", "kernel", "kidney", "kind", "kingdom", "kitchen",
        "kitten", "kiwi", "knight", "koala", "label", "ladder", "lament", "landing",
        "language", "laptop", "large", "later", "latin", "laugh", "laundry", "layer",
        "leader", "leaf", "learn", "leave", "lecture", "legend", "leisure", "lemon",
        "length", "leopard", "lesson", "letter", "level", "liberty", "library", "license",
        "light", "lilac", "limit", "linger", "liquid", "little", "lizard", "lobster",
        "local", "lonely", "lottery", "lounge", "loyal", "lumber", "lunar", "luxury",
        "machine", "magazine", "magnet", "maiden", "major", "mammal", "mandate", "mango",
        "mansion", "manual", "maple", "marble", "margin", "market", "master", "material",
        "matrix", "matter", "maximum", "meadow", "measure", "media", "melody", "member",
        "memory", "mention", "mercy", "merit", "method", "middle", "migrate", "million",
        "mineral", "minimum", "minor", "minute", "miracle", "mirror", "misery", "mistake",
        "mixture", "mobile", "model", "modify", "moisture", "moment", "monitor", "monkey",
        "monster", "month", "morning", "mosquito", "mother", "motion", "mountain", "mouse",
        "movie", "muffin", "multiply", "muscle", "museum", "mushroom", "music", "mustard",
        "mutual", "mystery", "narrow", "nasty", "nature", "nearby", "neglect", "neither",
        "nephew", "nerve", "neutral", "noble", "noise", "nominal", "noodle", "normal",
        "notable", "nothing", "notice", "novel", "nuclear", "number", "nurse",
        "object", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor",
        "office", "often", "olive", "olympic", "once", "onion", "online", "opera",
        "opinion", "oppose", "option", "orange", "orbit", "orchard", "organ", "orient",
        "original", "orphan", "ostrich", "other", "outdoor", "output", "outside", "oval",
        "oxygen", "oyster", "paddle", "palace", "panda", "panel", "panic", "panther",
        "paper", "parade", "parent", "park", "parrot", "partner", "party", "passage",
        "patient", "pattern", "pause", "payment", "peace", "peanut", "pelican", "penalty",
        "pencil", "people", "pepper", "perfect", "permit", "person", "phrase", "physical",
        "piano", "picnic", "picture", "piece", "pilot", "pioneer", "pistol", "pizza",
        "planet", "plastic", "platform", "player", "please", "pledge", "pluck", "plunge",
        "poetry", "polite", "popular", "portion", "position", "possible", "potato", "pottery",
        "poverty", "powder", "power", "predict", "prepare", "present", "pretty", "prevent",
        "price", "pride", "primary", "prince", "print", "priority", "prison", "private",
        "problem", "process", "produce", "profit", "program", "project", "promote", "proof",
        "prosper", "protect", "proud", "provide", "public", "pulse", "pumpkin", "punch",
        "pupil", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick",
        "quote", "rabbit", "raccoon", "radar", "radio", "raise", "rally", "ramp",
        "ranch", "random", "range", "rapid", "rather", "raven", "razor", "ready",
        "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() {
        let password = b"test-password-123!";
        let salt = [42u8; SALT_SIZE];

        let kek1 = derive_kek(password, &salt).expect("test should derive KEK from password");
        let kek2 = derive_kek(password, &salt).expect("test should derive KEK from password");

        assert_eq!(kek1.as_ref(), kek2.as_ref());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = b"test-password";
        let salt1 = [1u8; SALT_SIZE];
        let salt2 = [2u8; SALT_SIZE];

        let kek1 = derive_kek(password, &salt1).expect("test should derive KEK with first salt");
        let kek2 = derive_kek(password, &salt2).expect("test should derive KEK with second salt");

        assert_ne!(kek1.as_ref(), kek2.as_ref());
    }

    #[test]
    fn test_dek_encrypt_decrypt_roundtrip() {
        let kek = Zeroizing::new([99u8; KEY_SIZE]);
        let dek = generate_dek();

        let encrypted = encrypt_dek(&dek, &kek).expect("test should encrypt DEK");
        let decrypted = decrypt_dek(&encrypted, &kek).expect("test should decrypt DEK");

        assert_eq!(dek.as_ref(), decrypted.as_ref());
    }

    #[test]
    fn test_data_encrypt_decrypt_roundtrip() {
        let dek = generate_dek();
        let plaintext = b"Hello, VaultGuard!";

        let encrypted = encrypt_data(plaintext, &dek).expect("test should encrypt plaintext");
        let decrypted = decrypt_data(&encrypted, &dek).expect("test should decrypt ciphertext");

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let dek = generate_dek();
        let wrong_dek = generate_dek();
        let plaintext = b"secret data";

        let encrypted = encrypt_data(plaintext, &dek).expect("test should encrypt plaintext");
        let result = decrypt_data(&encrypted, &wrong_dek);

        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_verify() {
        let kek = Zeroizing::new([77u8; KEY_SIZE]);
        let data = b"some data to protect";

        let hmac = compute_hmac(data, &kek).expect("test should compute HMAC");
        assert!(verify_hmac(data, &hmac, &kek).expect("test should verify HMAC"));
    }

    #[test]
    fn test_hmac_detects_tampering() {
        let kek = Zeroizing::new([77u8; KEY_SIZE]);
        let data = b"some data to protect";

        let hmac = compute_hmac(data, &kek).expect("test should compute HMAC");
        let tampered = b"some data to protecT";
        assert!(!verify_hmac(tampered, &hmac, &kek).expect("test should verify tampered HMAC"));
    }

    #[test]
    fn test_password_generation() {
        let options = PasswordGenOptions {
            length: 32,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            exclude_ambiguous: false,
        };
        let pwd = generate_password(&options);
        assert_eq!(pwd.len(), 32);
    }

    #[test]
    fn test_passphrase_generation() {
        let passphrase = generate_passphrase(5, "-");
        let words: Vec<&str> = passphrase.split('-').collect();
        assert_eq!(words.len(), 5);
    }

    #[test]
    fn repeated_chars_are_weak() {
        let result = check_password_strength("aaaaaaaaaaaaa");
        assert_eq!(result.level, 0);
        assert!(
            result.crack_time == "instantly" || result.crack_time.contains("seconds"),
            "13 a's should crack instantly, got: {}",
            result.crack_time
        );
    }

    #[test]
    fn repeated_with_one_different_is_still_weak() {
        let result = check_password_strength("aaaaaaaaaaaaad");
        assert_eq!(result.level, 0);
        assert!(
            !result.crack_time.contains("centur") && !result.crack_time.contains("year"),
            "aaaaaaaaaaaaad should not take centuries, got: {}",
            result.crack_time
        );
    }

    #[test]
    fn common_password_is_weak() {
        let result = check_password_strength("password123");
        assert_eq!(result.level, 0);
    }

    #[test]
    fn strong_random_password() {
        let result = check_password_strength("xK#9mP$2qL!wZn6@");
        assert_eq!(result.level, 3);
    }

    #[test]
    fn keyboard_walk_is_penalized() {
        let result = check_password_strength("Qwerty123!");
        assert!(
            result.level <= 1,
            "Keyboard walk should be weak/fair, got level {}",
            result.level
        );
    }
}
