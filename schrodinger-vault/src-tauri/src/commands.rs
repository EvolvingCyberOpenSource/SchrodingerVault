use crate::state::AppDb;
use crate::vault_core::db::{self, EntryListItem, NewEntry};
use rusqlite::{params, Connection, OptionalExtension};
use tauri::{command, AppHandle, State};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::{rng, RngCore}; // rand 0.9: rng() + RngCore::fill_bytes (reserved for future nonce use)

use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use dirs;
use oqs; // high-level, safe wrappers
use secrecy::{ExposeSecret, SecretString};
use std::fs::OpenOptions;
use std::io::Write;
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

#[path = "commands_clipboard.rs"]
pub mod commands_clipboard;
use commands_clipboard::copy_to_clipboard;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};

// TODO: Refactor. This file is messy and way too long (almost 900 lines as of writing this !!!!),
// we will need to refactor and organize functions into other files when the core functionality is done
// and call them here. and also add documentation and refine comments

// =========================
// Session AES key (RAM-only)
// =========================

//previous:
//pub static VAULT_AES_KEY: RwLock<Option<[u8; 32]>> = RwLock::new(None);

// Store AES-256 session key wrapped in Zeroizing so it is wiped on lock/exit. #new

pub static VAULT_AES_KEY: std::sync::RwLock<Option<Zeroizing<[u8; 32]>>> =
    std::sync::RwLock::new(None);

// =========================
// RwLock helper functions
// =========================

// Installs AES key in RAM (old key auto-wiped by Zeroizing on replace) #new
pub fn install_aes_key(key: &[u8; 32]) -> Result<(), &'static str> {
    let mut guard = VAULT_AES_KEY.write().map_err(|_| "lock poisoned")?;
    *guard = Some(wrap_key(*key));
    Ok(())
}

// Alternate function to get_aes_key which returns a reference instead of a stack copy, no need to zeroize.
// Must use a guard when using this function. When guard is dropped the reference disppears.

// Example:
// let guard = get_aes_key_ref()?;
// let aes_key = guard.as_ref();

fn get_aes_key_ref<'a>(
) -> Result<std::sync::RwLockReadGuard<'a, Option<Zeroizing<[u8; 32]>>>, &'static str> {
    VAULT_AES_KEY.read().map_err(|_| "lock poisoned")
}

// Wipe currently installed AES key (dropping Zeroizing wipes memory) #new
fn zeroize_aes_key() -> Result<(), &'static str> {
    let mut guard = VAULT_AES_KEY.write().map_err(|_| "lock poisoned")?;
    if let Some(ref mut key) = *guard {
        key.zeroize(); // zero memory
    }
    *guard = None; // also remove key
    Ok(())
}

// Zeroization helpers  #new
//
// Why: Dropping a variable doesn't always erase its bytes from RAM. We use
// the zeroize crate to overwrite sensitive data (passwords, keys) as soon
// as we're done using them.

/// Overwrite a mutable buffer with zeros.
fn wipe_secret(buf: &mut [u8]) {
    buf.zeroize();
}

/// Wrap a 32-byte key so it auto-wipes on drop.
fn wrap_key(key: [u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(key)
}
// ====================
// AES-256-GCM helpers
// ====================

// Generate nonce
fn new_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    rand::rng().fill_bytes(&mut n);
    n
}
// Holds the per-entry nonce, ciphertext, and authentication tag
struct SealResult {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}

fn encrypt_password(aes_key: &[u8; 32], password_utf8: &str) -> Result<SealResult, String> {
    let password_utf8 = SecretString::from(password_utf8);
    let key = GenericArray::from_slice(aes_key);
    let cipher = Aes256Gcm::new(key);

    let nonce = new_nonce();
    let nonce_ga = Nonce::from_slice(&nonce);

    // In-place so we don't keep two plaintext copies
    let mut buf = Zeroizing::new(password_utf8.expose_secret().as_bytes().to_vec());
    let tag = cipher
        .encrypt_in_place_detached(nonce_ga, b"", &mut buf)
        .map_err(|e| e.to_string())?;

    let mut out_tag = [0u8; 16];
    out_tag.copy_from_slice(tag.as_slice());
    let ciphertext = buf.to_vec();

    Ok(SealResult {
        nonce,
        ciphertext,
        tag: out_tag,
    })
}

fn decrypt_password(
    aes_key: &[u8; 32],
    nonce: &[u8; 12],
    mut ciphertext: Vec<u8>,
    tag: &[u8; 16],
) -> Result<SecretString, String> {
    let key = GenericArray::from_slice(aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = Nonce::from_slice(nonce);
    let tag_ga = GenericArray::from_slice(tag);

    cipher
        .decrypt_in_place_detached(nonce_ga, b"", &mut ciphertext, tag_ga)
        .map_err(|_| "Couldn't decrypt entry. It may be corrupted or tampered.".to_string())?;

    let password = String::from_utf8(ciphertext)
        .map_err(|_| "Decrypted data was not valid UTF-8".to_string())?;
    Ok(SecretString::from(password))
}

// =========================
// Keystore helpers (KEM SK)
// =========================

/// Write a secret key file with tight permissions:
/// - Unix/macOS: 0600
/// - Windows: per-user ACL in %LOCALAPPDATA%
fn write_secret_key_secure(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        let mut p = f.metadata()?.permissions();
        p.set_mode(0o600);
        fs::set_permissions(path, p)?;
        Ok(())
    }

    #[cfg(windows)]
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        Ok(())
    }
}

/// %LOCALAPPDATA%/SchrodingerVault/keystore/mlkem768.sk (Windows)
/// ~/Library/Application Support/SchrodingerVault/keystore/mlkem768.sk (macOS)
/// ~/.local/share/SchrodingerVault/keystore/mlkem768.sk (Linux)
fn keystore_path() -> io::Result<PathBuf> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no local data dir"))?;
    let dir = base.join("SchrodingerVault").join("keystore");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("mlkem768.sk"))
}

#[command]
pub fn vault_exists(db: State<AppDb>) -> Result<bool, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(1) FROM meta WHERE key IN (
                'salt_pw',
                'salt_kdf',
                'pk_kem',
                'ct_kem',
                'verifier_nonce',
                'verifier_ct'
            )",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(count == 6)
}

#[derive(serde::Serialize)]
pub struct VaultSessionStatus {
    pub loaded: bool,
}

#[command]
pub fn vault_session_status() -> Result<VaultSessionStatus, String> {
    let guard = VAULT_AES_KEY.read().map_err(|_| "lock poisoned")?;
    Ok(VaultSessionStatus {
        loaded: guard.is_some(),
    })
}

// =========================
// Vault creation (Step 5–7)
// DB schema is created by vault_core::db::open_and_init in main.rs setup
// =========================

#[command]
pub fn create_vault(
    _app: AppHandle,
    db: State<AppDb>,
    master_password: String,
) -> Result<bool, String> {
    let master_password = SecretString::from(master_password);

    // Use the live, already-initialized connection
    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let existing_meta_count: i64 = conn
        .query_row(
            "SELECT COUNT(1) FROM meta WHERE key IN (
                'salt_pw',
                'salt_kdf',
                'pk_kem',
                'ct_kem',
                'verifier_nonce',
                'verifier_ct'
            )",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let existing_entries_count: i64 = conn
        .query_row("SELECT COUNT(1) FROM entries", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if existing_meta_count == 6 || existing_entries_count > 0 {
        return Err("A vault already exists. Unlock it or use Reset Vault from Settings.".into());
    }

    // salts (random)
    let mut r = rng();
    let mut salt_pw = [0u8; 32];
    let mut salt_kdf = [0u8; 32];
    r.fill_bytes(&mut salt_pw);
    r.fill_bytes(&mut salt_kdf);

    // Base64 for TEXT storage
    let salt_pw_b64 = B64.encode(salt_pw);
    let salt_kdf_b64 = B64.encode(salt_kdf);

    // PBKDF2 params
    let kdf = "pbkdf2-hmac-sha256";
    let kdf_params = r#"{"iterations":310000,"out":32,"algo":"sha256"}"#;

    // PBKDF2 derive K1 (RAM only)
    let iterations: u32 = 310_000;
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        master_password.expose_secret().as_bytes(),
        &salt_pw,
        iterations.into(),
        &mut k1,
    );

    {
        use aes_gcm::{
            aead::{rand_core::RngCore, Aead, OsRng},
            Aes256Gcm, KeyInit,
        };
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        let verifier_plain = b"vault-ok";
        let cipher = Aes256Gcm::new_from_slice(&k1).unwrap();

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let verifier_ct = cipher
            .encrypt(&nonce.into(), verifier_plain.as_ref())
            .expect("verifier encryption failed");

        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('verifier_nonce', ?1)",
            [B64.encode(&nonce)],
        )
        .map_err(|_| "insert verifier_nonce failed")?;

        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('verifier_ct', ?1)",
            [B64.encode(&verifier_ct)],
        )
        .map_err(|_| "insert verifier_ct failed")?;
    }

    // Device KEM keypair + self-encapsulation (returns pk, ct, ss)
    let (pk_kem_raw, ct_kem_raw) = generate_device_keypair().map_err(|e| e.to_string())?;

    // =======================================
    // ML-DSA KEYPAIR (signatures for manifest)
    // =======================================
    use oqs::sig::{Algorithm as SigAlgorithm, Sig};

    let dsa = Sig::new(SigAlgorithm::MlDsa65).map_err(|e| format!("ML-DSA init failed: {}", e))?;

    let (dsa_pk, dsa_sk) = dsa
        .keypair()
        .map_err(|e| format!("ML-DSA keypair failed: {}", e))?;

    let dsa_pk_b64 = B64.encode(dsa_pk.as_ref());

    // store ML-DSA public key in meta
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('dsa_pk', ?1)",
        [&dsa_pk_b64],
    )
    .map_err(|e| format!("insert dsa_pk failed: {}", e))?;

    // store ML-DSA secret key on disk next to mlkem768.sk
    let mut dsa_sk_path = keystore_path().map_err(|e| e.to_string())?;
    dsa_sk_path.set_file_name("ml_dsa.sk");

    write_secret_key_secure(&dsa_sk_path, dsa_sk.as_ref())
        .map_err(|e| format!("write ML-DSA secret key failed: {}", e))?;

    // Base64 for TEXT meta
    let pk_kem_b64 = B64.encode(&pk_kem_raw);
    let ct_kem_b64 = B64.encode(&ct_kem_raw);
    let kem_alg = "ML-KEM-768";

    // Store public/metadata only
    {
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"salt_pw", &salt_pw_b64),
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"salt_kdf", &salt_kdf_b64),
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"kdf", kdf),
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"kdf_params", kdf_params),
        )
        .map_err(|e| e.to_string())?;

        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"pk_kem", &pk_kem_b64),
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"ct_kem", &ct_kem_b64),
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"kem_alg", kem_alg),
        )
        .map_err(|e| e.to_string())?;

        // algorithm label string for the vault (public)
        let alg = "mlkem768|aes256gcm|hkdfsha256|pbkdf2";
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"alg", alg),
        )
        .map_err(|e| e.to_string())?;

        tx.commit().map_err(|e| e.to_string())?;
        // Immediately wipe K1 after it's used for verifier + meta storage (intermediate secret)
        wipe_secret(&mut k1);
    }

    // --- Manifest creation for tamper detection ---
    {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use sha2::{Digest, Sha256};

        // Re-acquire a read handle
        let mut manifest_input = String::new();
        for key in [
            "salt_pw",
            "salt_kdf",
            "pk_kem",
            "ct_kem",
            "verifier_nonce",
            "verifier_ct",
        ] {
            let value: String = conn
                .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap_or_default();
            manifest_input.push_str(&value);
        }

        // Compute hash
        let manifest_hash = Sha256::digest(manifest_input.as_bytes());
        let manifest_b64 = B64.encode(manifest_hash);

        // -------- REAL ML-DSA SIGNATURE --------

        let mut dsa_sk_path = keystore_path().map_err(|e| e.to_string())?;
        dsa_sk_path.set_file_name("ml_dsa.sk");

        let dsa_sk_bytes =
            std::fs::read(&dsa_sk_path).map_err(|e| format!("read ml_dsa.sk failed: {e}"))?;

        let dsa =
            Sig::new(SigAlgorithm::MlDsa65).map_err(|e| format!("ML-DSA init failed: {}", e))?;

        let dsa_sk_ref = dsa
            .secret_key_from_bytes(&dsa_sk_bytes)
            .ok_or("Invalid ML-DSA secret key")?;

        let sig = dsa
            .sign(manifest_hash.as_ref(), dsa_sk_ref)
            .map_err(|e| format!("ML-DSA sign failed: {}", e))?;

        let signature_b64 = B64.encode(sig.as_ref());

        // Store both into meta
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('manifest_hash', ?1)",
            [&manifest_b64],
        )
        .map_err(|e| format!("insert manifest_hash failed: {e}"))?;

        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('manifest_sig', ?1)",
            [&signature_b64],
        )
        .map_err(|e| format!("insert manifest_sig failed: {e}"))?;
    }
    Ok(true)
}

// Step 2 helper — Recover device secret (ss) using ML-KEM-768

/// Step 2: Recover the device-bound shared secret (ss) by decapsulating ML-KEM-768.
/// Inputs:
///   - ct_kem (Base64) from meta
///   - sk_kem (raw bytes) from keystore (0600 perms on Unix, per-user ACL on Windows)
/// Output:
///   - 32-byte ss (in RAM only). The caller is responsible for zeroizing it after use.
/// Errors:
///   - Missing device SK → "device secret key missing; vault cannot unlock on this device"
///   - Corrupted/invalid ciphertext → "decapsulate failed ..."
// ===================================================================
// Step 2 helper — Recover device secret (ss) via ML-KEM-768 (fixed API)
// ===================================================================

/// Step 2: Recover the device-bound shared secret (ss) by decapsulating ML-KEM-768.
/// Inputs:
///   - ct_kem (Base64) from meta
///   - sk_kem (raw bytes) from keystore (0600 perms on Unix, per-user ACL on Windows)
/// Output:
///   - 32-byte ss (in RAM only). The caller is responsible for zeroizing it after use.
/// Errors:
///   - Missing device SK → "device secret key missing; vault cannot unlock on this device"
///   - Corrupted/invalid ciphertext → "decapsulation failed ..." or length/decoding errors
fn recover_device_secret(db: &State<AppDb>) -> Result<[u8; 32], String> {
    use oqs::kem::{Algorithm, Kem};

    // 1) Fetch ct_kem (b64) from meta
    let ct_kem_b64: String = {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        conn.query_row("SELECT value FROM meta WHERE key='ct_kem'", [], |r| {
            r.get::<_, String>(0)
        })
        .map_err(|_| "missing meta key: ct_kem".to_string())?
    };

    // 2) Decode ct_kem
    let ct_kem_bytes = B64
        .decode(ct_kem_b64.as_bytes())
        .map_err(|_| "ct_kem decode failed".to_string())?;

    // 3) Load device SK from keystore
    let sk_path = keystore_path().map_err(|e| format!("keystore path: {e}"))?;
    if !sk_path.exists() {
        return Err("device secret key missing; vault cannot unlock on this device".into());
    }
    let mut sk_bytes = fs::read(&sk_path).map_err(|e| format!("read device secret key: {e}"))?;

    // 4) KEM decapsulation → ss (32 bytes)
    oqs::init();
    let kem = Kem::new(Algorithm::MlKem768).map_err(|e| format!("kem new: {e}"))?;

    // Build *validated* refs from raw bytes via Kem helpers
    let sk_ref = kem
        .secret_key_from_bytes(&sk_bytes)
        .ok_or_else(|| "secret key length invalid/corrupted".to_string())?;
    let ct_ref = kem
        .ciphertext_from_bytes(&ct_kem_bytes)
        .ok_or_else(|| "ciphertext length invalid/corrupted".to_string())?;

    let ss_vec = kem
        .decapsulate(sk_ref, ct_ref)
        .map_err(|e| format!("decapsulation failed (ciphertext may be corrupted): {e}"))?;

    // Copy to fixed-size array
    if ss_vec.as_ref().len() != 32 {
        return Err(format!("unexpected ss length: {}", ss_vec.as_ref().len()));
    }
    let mut ss = [0u8; 32];
    ss.copy_from_slice(ss_vec.as_ref());

    // Zeroize sensitive SK bytes read from disk
    sk_bytes.zeroize();

    Ok(ss)
}

fn kdf_iterations(kdf_params_json: Option<String>) -> u32 {
    kdf_params_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| {
            v.get("iterations")
                .and_then(|i| i.as_u64())
                .map(|n| n as u32)
        })
        .unwrap_or(310_000)
}

fn derive_k1(password: &SecretString, salt_pw: &[u8], iterations: u32) -> [u8; 32] {
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.expose_secret().as_bytes(),
        salt_pw,
        iterations,
        &mut k1,
    );
    k1
}

fn verify_k1(conn: &Connection, k1: &[u8; 32]) -> Result<(), String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

    let nonce_b64: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key='verifier_nonce'",
            [],
            |r| r.get::<_, String>(0),
        )
        .map_err(|_| "missing verifier_nonce")?;
    let ct_b64: String = conn
        .query_row("SELECT value FROM meta WHERE key='verifier_ct'", [], |r| {
            r.get::<_, String>(0)
        })
        .map_err(|_| "missing verifier_ct")?;

    let nonce = B64.decode(&nonce_b64).map_err(|_| "nonce decode failed")?;
    let ct = B64
        .decode(&ct_b64)
        .map_err(|_| "verifier_ct decode failed")?;
    let nonce_ga = GenericArray::from_slice(&nonce);

    let cipher = Aes256Gcm::new_from_slice(k1).map_err(|_| "cipher init failed")?;
    let plaintext = cipher
        .decrypt(nonce_ga, ct.as_ref())
        .map_err(|_| "That password didn’t work.".to_string())?;

    if plaintext != b"vault-ok" {
        return Err("That password didn’t work.".into());
    }

    Ok(())
}

fn derive_vault_key(k1: &[u8; 32], salt_kdf: &[u8], ss: &[u8; 32]) -> Result<[u8; 32], String> {
    let hk_k1 = Hkdf::<Sha256>::new(Some(salt_kdf), k1);
    let mut prk1 = [0u8; 32];
    hk_k1.expand(&[], &mut prk1).map_err(|e| e.to_string())?;

    let hk_final = Hkdf::<Sha256>::new(Some(&prk1), ss);
    let mut aes_key = [0u8; 32];
    hk_final
        .expand(b"vault-key", &mut aes_key)
        .map_err(|_| "HKDF expand failed".to_string())?;

    prk1.zeroize();
    Ok(aes_key)
}

fn verify_master_password(conn: &Connection, password: &SecretString) -> Result<(), String> {
    let salt_pw_b64: String = conn
        .query_row("SELECT value FROM meta WHERE key='salt_pw'", [], |r| {
            r.get::<_, String>(0)
        })
        .map_err(|_| "missing meta key: salt_pw")?;
    let kdf_params_json: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key='kdf_params'", [], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .map_err(|e| e.to_string())?;

    let salt_pw = B64
        .decode(&salt_pw_b64)
        .map_err(|_| "salt_pw decode failed")?;
    let iterations = kdf_iterations(kdf_params_json);
    let mut k1 = derive_k1(password, &salt_pw, iterations);
    let result = verify_k1(conn, &k1);
    k1.zeroize();
    result
}

fn sign_manifest_input(manifest_input: &str) -> Result<(String, String), String> {
    use oqs::sig::{Algorithm as SigAlgorithm, Sig};
    use sha2::{Digest, Sha256};

    let manifest_hash = Sha256::digest(manifest_input.as_bytes());
    let manifest_b64 = B64.encode(manifest_hash);

    let mut dsa_sk_path = keystore_path().map_err(|e| e.to_string())?;
    dsa_sk_path.set_file_name("ml_dsa.sk");
    let mut dsa_sk_bytes =
        std::fs::read(&dsa_sk_path).map_err(|e| format!("read ml_dsa.sk failed: {e}"))?;

    let dsa = Sig::new(SigAlgorithm::MlDsa65).map_err(|e| format!("ML-DSA init failed: {}", e))?;
    let dsa_sk_ref = dsa
        .secret_key_from_bytes(&dsa_sk_bytes)
        .ok_or("Invalid ML-DSA secret key")?;
    let sig = dsa
        .sign(manifest_hash.as_ref(), dsa_sk_ref)
        .map_err(|e| format!("ML-DSA sign failed: {}", e))?;
    dsa_sk_bytes.zeroize();

    Ok((manifest_b64, B64.encode(sig.as_ref())))
}

#[command]
pub fn unlock_vault(_app: AppHandle, db: State<AppDb>, password: String) -> Result<bool, String> {
    let master_password = SecretString::from(password);

    // getting salt_pw and kdf info from meta table
    let (salt_pw_b64, _kdf_label, kdf_params_json): (String, String, Option<String>) = {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let get = |k: &str| -> Result<String, String> {
            conn.query_row("SELECT value FROM meta WHERE key=?1", [k], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| format!("missing meta key: {k}"))
        };
        (
            get("salt_pw")?,
            get("kdf")?,
            conn.query_row("SELECT value FROM meta WHERE key='kdf_params'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .map_err(|e| e.to_string())?,
        )
    };

    // decodeing salt_pw
    let salt_pw = B64
        .decode(&salt_pw_b64)
        .map_err(|_| "salt_pw decode failed")?;

    // getting num of pbdkf2 iterations (uses 310_000 as a default)
    let iterations: u32 = kdf_params_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| {
            v.get("iterations")
                .and_then(|i| i.as_u64())
                .map(|n| n as u32)
        })
        .unwrap_or(310_000);

    // deriving k1
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        master_password.expose_secret().as_bytes(),
        &salt_pw,
        iterations,
        &mut k1,
    );

    {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        // Fetch verifier data from DB
        let (nonce_b64, ct_b64): (String, String) = {
            let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
            (
                conn.query_row(
                    "SELECT value FROM meta WHERE key='verifier_nonce'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .map_err(|_| "missing verifier_nonce")?,
                conn.query_row("SELECT value FROM meta WHERE key='verifier_ct'", [], |r| {
                    r.get::<_, String>(0)
                })
                .map_err(|_| "missing verifier_ct")?,
            )
        };

        // Decode Base64 verifier data
        let nonce = B64.decode(&nonce_b64).map_err(|_| "nonce decode failed")?;
        let ct = B64
            .decode(&ct_b64)
            .map_err(|_| "verifier_ct decode failed")?;

        // Convert nonce into AES-GCM GenericArray (required by decrypt)
        let nonce_ga = GenericArray::from_slice(&nonce);

        // Attempt to decrypt verifier with derived K1
        let cipher = Aes256Gcm::new_from_slice(&k1).map_err(|_| "cipher init failed")?;
        match cipher.decrypt(nonce_ga, ct.as_ref()) {
            Ok(plaintext) => {
                if plaintext != b"vault-ok" {
                    k1.zeroize();
                    return Err("That password didn’t work.".into());
                }
            }
            Err(_) => {
                k1.zeroize();
                return Err("That password didn’t work.".into());
            }
        }
    }

    // --- Manifest verification for tamper detection ---
    {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use oqs::sig::{Algorithm as SigAlgorithm, Sig};
        use sha2::{Digest, Sha256};

        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

        // 1) Rebuild manifest input exactly like in create_vault
        let mut manifest_input = String::new();
        for key in [
            "salt_pw",
            "salt_kdf",
            "pk_kem",
            "ct_kem",
            "verifier_nonce",
            "verifier_ct",
        ] {
            let value: String = conn
                .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap_or_default();
            manifest_input.push_str(&value);
        }

        // 2) Compute fresh SHA-256 hash and base64-encode it
        let manifest_hash = Sha256::digest(manifest_input.as_bytes());
        let manifest_b64 = B64.encode(manifest_hash);

        // 3) Load stored manifest hash + signature + ML-DSA public key
        let stored_hash_b64: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key='manifest_hash'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "missing manifest_hash")?;

        let stored_sig_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='manifest_sig'", [], |r| {
                r.get(0)
            })
            .map_err(|_| "missing manifest_sig")?;

        let dsa_pk_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='dsa_pk'", [], |r| {
                r.get(0)
            })
            .map_err(|_| "missing dsa_pk")?;

        // 4) First check: hash equality (simple tamper check)
        if manifest_b64 != stored_hash_b64 {
            k1.zeroize();
            return Err(
                "This vault has been modified outside of Schrödinger Vault. Unlock blocked.".into(),
            );
        }

        // 5) Decode signature + public key from base64
        let sig_bytes = B64
            .decode(stored_sig_b64.as_bytes())
            .map_err(|_| "manifest_sig decode failed")?;

        let pk_bytes = B64
            .decode(dsa_pk_b64.as_bytes())
            .map_err(|_| "dsa_pk decode failed")?;

        // 6) Initialize ML-DSA verifier
        let dsa =
            Sig::new(SigAlgorithm::MlDsa65).map_err(|e| format!("ML-DSA init failed: {}", e))?;

        let pk_ref = dsa
            .public_key_from_bytes(&pk_bytes)
            .ok_or("Invalid ML-DSA public key")?;

        let sig_ref = dsa
            .signature_from_bytes(&sig_bytes)
            .ok_or("Invalid ML-DSA signature")?;

        // manifest_hash is raw bytes; we signed exactly these bytes in create_vault
        if let Err(_e) = dsa.verify(manifest_hash.as_ref(), sig_ref, pk_ref) {
            k1.zeroize();
            return Err(
                "This vault has been modified outside of Schrödinger Vault. Unlock blocked.".into(),
            );
        }
    }

    // Implemented: Step 2 decapsulation to recover ss (RAM-only). check recover_device_secret function above unlock_vault command
    match recover_device_secret(&db) {
        Ok(ss) => {
            let mut ss_zero = ss;

            // Load salt_kdf in b64 from meta
            let salt_kdf_b64: String = {
                let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
                conn.query_row("SELECT value FROM meta WHERE key='salt_kdf'", [], |r| {
                    r.get::<_, String>(0)
                })
                .map_err(|_| "missing meta key: salt_kdf")?
            };

            // Decode from b64
            let salt_kdf = B64
                .decode(&salt_kdf_b64)
                .map_err(|_| "salt_kdf decode failed")?;

            // Blend K1 and ss via HKDF-SHA256
            let hk_k1 = Hkdf::<Sha256>::new(Some(&salt_kdf), &k1);
            let mut prk1 = [0u8; 32];
            hk_k1.expand(&[], &mut prk1).map_err(|e| e.to_string())?;

            // HKDF-Extract again with ss, using prk1 as salt
            let hk_final = Hkdf::<Sha256>::new(Some(&prk1), &ss_zero);

            // Expand to AES key
            let mut aes_key_tmp = [0u8; 32];
            hk_final
                .expand(b"vault-key", &mut aes_key_tmp)
                .map_err(|_| "HKDF expand failed")?;

            // #new
            // Wrap AES key so it wipes automatically when dropped, then install.
            let _ = install_aes_key(&aes_key_tmp);

            // Zeroize sensitive inputs immediately
            prk1.zeroize();
            ss_zero.zeroize();
            k1.zeroize();

            return Ok(true);
        }
        Err(_e) => {
            // Explicit, user-friendly error if SK missing or ct_kem corrupted
            k1.zeroize();
            return Err(
                "Vault cannot be unlocked — device key missing or vault data corrupted.".into(),
            );
        }
    }
}

#[command]
pub fn change_master_password(
    db: State<AppDb>,
    current_password: String,
    new_password: String,
) -> Result<bool, String> {
    if current_password.is_empty() {
        return Err("Current master password is required".into());
    }
    if new_password.len() < 10 {
        return Err("New master password must be at least 10 characters".into());
    }
    if current_password == new_password {
        return Err("New master password must be different".into());
    }

    let current_password = SecretString::from(current_password);
    let new_password = SecretString::from(new_password);

    let mut ss = recover_device_secret(&db)?;
    let mut old_k1 = [0u8; 32];
    let mut old_aes_key = [0u8; 32];
    let mut new_k1 = [0u8; 32];
    let mut new_aes_key = [0u8; 32];

    let result = (|| -> Result<bool, String> {
        let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

        let salt_pw_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='salt_pw'", [], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| "missing meta key: salt_pw")?;
        let pk_kem_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='pk_kem'", [], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| "missing meta key: pk_kem")?;
        let ct_kem_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='ct_kem'", [], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| "missing meta key: ct_kem")?;
        let salt_kdf_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='salt_kdf'", [], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| "missing meta key: salt_kdf")?;
        let kdf_params_json: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key='kdf_params'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .map_err(|e| e.to_string())?;

        let salt_pw = B64
            .decode(&salt_pw_b64)
            .map_err(|_| "salt_pw decode failed")?;
        let salt_kdf = B64
            .decode(&salt_kdf_b64)
            .map_err(|_| "salt_kdf decode failed")?;
        let iterations = kdf_iterations(kdf_params_json);

        old_k1 = derive_k1(&current_password, &salt_pw, iterations);
        verify_k1(&conn, &old_k1)?;
        old_aes_key = derive_vault_key(&old_k1, &salt_kdf, &ss)?;

        let mut plaintext_entries: Vec<(i64, SecretString)> = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT id, nonce, ciphertext, tag FROM entries ORDER BY id")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                })
                .map_err(|e| e.to_string())?;

            for row in rows {
                let (id, nonce, ciphertext, tag) = row.map_err(|e| e.to_string())?;
                if nonce.len() != 12 || tag.len() != 16 {
                    return Err("Entry is corrupt (invalid nonce/tag size)".into());
                }
                let mut nonce12 = [0u8; 12];
                nonce12.copy_from_slice(&nonce);
                let mut tag16 = [0u8; 16];
                tag16.copy_from_slice(&tag);
                let secret = decrypt_password(&old_aes_key, &nonce12, ciphertext, &tag16)?;
                nonce12.zeroize();
                tag16.zeroize();
                plaintext_entries.push((id, secret));
            }
        }

        let mut r = rng();
        let mut new_salt_pw = [0u8; 32];
        let mut new_salt_kdf = [0u8; 32];
        r.fill_bytes(&mut new_salt_pw);
        r.fill_bytes(&mut new_salt_kdf);

        new_k1 = derive_k1(&new_password, &new_salt_pw, iterations);
        new_aes_key = derive_vault_key(&new_k1, &new_salt_kdf, &ss)?;

        let cipher = Aes256Gcm::new_from_slice(&new_k1).map_err(|_| "cipher init failed")?;
        let mut verifier_nonce = [0u8; 12];
        r.fill_bytes(&mut verifier_nonce);
        let verifier_ct = cipher
            .encrypt(&verifier_nonce.into(), b"vault-ok".as_ref())
            .map_err(|_| "verifier encryption failed".to_string())?;

        let new_salt_pw_b64 = B64.encode(new_salt_pw);
        let new_salt_kdf_b64 = B64.encode(new_salt_kdf);
        let verifier_nonce_b64 = B64.encode(verifier_nonce);
        let verifier_ct_b64 = B64.encode(&verifier_ct);
        let manifest_input = format!(
            "{}{}{}{}{}{}",
            new_salt_pw_b64,
            new_salt_kdf_b64,
            pk_kem_b64,
            ct_kem_b64,
            verifier_nonce_b64,
            verifier_ct_b64
        );
        let (manifest_hash_b64, manifest_sig_b64) = sign_manifest_input(&manifest_input)?;

        let tx = conn.transaction().map_err(|e| e.to_string())?;
        for (id, secret) in &plaintext_entries {
            let sealed = encrypt_password(&new_aes_key, secret.expose_secret())?;
            tx.execute(
                r#"
                UPDATE entries
                SET nonce = ?1, ciphertext = ?2, tag = ?3,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                WHERE id = ?4
                "#,
                params![
                    sealed.nonce.as_slice(),
                    sealed.ciphertext.as_slice(),
                    sealed.tag.as_slice(),
                    id
                ],
            )
            .map_err(|e| e.to_string())?;
        }

        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('salt_pw', ?1)",
            [&new_salt_pw_b64],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('salt_kdf', ?1)",
            [&new_salt_kdf_b64],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('verifier_nonce', ?1)",
            [&verifier_nonce_b64],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('verifier_ct', ?1)",
            [&verifier_ct_b64],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('manifest_hash', ?1)",
            [&manifest_hash_b64],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('manifest_sig', ?1)",
            [&manifest_sig_b64],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;

        install_aes_key(&new_aes_key).map_err(|e| e.to_string())?;

        new_salt_pw.zeroize();
        new_salt_kdf.zeroize();
        verifier_nonce.zeroize();
        Ok(true)
    })();

    ss.zeroize();
    old_k1.zeroize();
    old_aes_key.zeroize();
    new_k1.zeroize();
    new_aes_key.zeroize();

    result
}

#[command]
pub fn lock_vault() {
    let _ = zeroize_aes_key();
    let _ = copy_to_clipboard(String::new());
}

/// Generates ML-KEM-768 keypair, encapsulates, self-checks decapsulation,
/// writes SK to keystore with tight perms, and returns (pk_raw, ct_raw, ss).
fn generate_device_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    oqs::init();

    let kem =
        oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).map_err(|e| format!("kem new: {e}"))?;

    let (pk_kem, sk_kem) = kem.keypair().map_err(|e| format!("keypair: {e}"))?;

    let (ct_kem, _ss_raw) = kem
        .encapsulate(&pk_kem)
        .map_err(|e| format!("encapsulate: {e}"))?;

    // Write SK securely to app-private keystore
    let sk_path = keystore_path().map_err(|e| format!("keystore_path: {e}"))?;
    write_secret_key_secure(&sk_path, sk_kem.as_ref()).map_err(|e| format!("write sk: {e}"))?;

    Ok((pk_kem.as_ref().to_vec(), ct_kem.as_ref().to_vec()))
}

// function is meant to be tirggered on a vault reset and then frontend should send user back to create vault screen
#[command]
pub fn factory_reset_vault(
    app: AppHandle,
    db: State<AppDb>,
    master_password: String,
) -> Result<bool, String> {
    if master_password.is_empty() {
        return Err("Master password is required to reset the vault".into());
    }
    {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let master_password = SecretString::from(master_password);
        verify_master_password(&conn, &master_password)?;
    }

    // delete ML-KEM key
    let sk_path = keystore_path().map_err(|e| e.to_string())?;
    remove_file_if_exists(&sk_path).ok();

    // delete ML-DSA key
    let mut dsa_path = keystore_path().map_err(|e| e.to_string())?;
    dsa_path.set_file_name("ml_dsa.sk");
    remove_file_if_exists(&dsa_path).ok();

    // delete meta + entries
    {
        let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;

        tx.execute(
            "DELETE FROM meta WHERE key IN (
                'salt_pw','salt_kdf','kdf','kdf_params',
                'pk_kem','ct_kem','kem_alg','alg',
                'manifest_hash','manifest_sig',
                'verifier_nonce','verifier_ct',
                'dsa_pk'
            )",
            [],
        )
        .map_err(|e| e.to_string())?;

        tx.execute("DELETE FROM entries", [])
            .map_err(|e| e.to_string())?;

        tx.commit().map_err(|e| e.to_string())?;
    }

    // release file lock + recreate DB
    {
        let mut guard = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let tmp = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
        let _old = std::mem::replace(&mut *guard, tmp);
    }

    let p = crate::vault_core::db::db_path(&app);
    let _ = std::fs::remove_file(&p);

    let new_conn = crate::vault_core::db::open_and_init(&app).map_err(|e| e.to_string())?;
    {
        let mut guard = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let _old = std::mem::replace(&mut *guard, new_conn);
    }

    Ok(true)
}

fn remove_file_if_exists(p: &Path) -> io::Result<()> {
    match fs::remove_file(p) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// =========================
// Debug helpers
// =========================

#[cfg(debug_assertions)]
mod debug_commands {
    use super::*;

    #[derive(serde::Serialize)]
    pub struct KemStatus {
        pub pk_kem_b64_len: usize,
        pub pk_kem_bytes_len: usize,
        pub ct_kem_b64_len: usize,
        pub ct_kem_bytes_len: usize,
        pub sk_path: String,
        pub sk_exists: bool,
        pub sk_len: Option<u64>,
        pub kem_alg: Option<String>,
    }

    #[command]
    pub fn debug_kem_status(db: State<AppDb>) -> Result<KemStatus, String> {
        let conn = db
            .inner()
            .0
            .lock()
            .map_err(|_| "DB lock poisoned".to_string())?;

        let pk_b64: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'pk_kem'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())?;

        let ct_b64: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'ct_kem'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())?;

        let kem_alg: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'kem_alg'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())?;

        let (pk_kem_b64_len, pk_kem_bytes_len) = match pk_b64 {
            Some(ref s) => (s.len(), B64.decode(s).map(|v| v.len()).unwrap_or(0)),
            None => (0, 0),
        };
        let (ct_kem_b64_len, ct_kem_bytes_len) = match ct_b64 {
            Some(ref s) => (s.len(), B64.decode(s).map(|v| v.len()).unwrap_or(0)),
            None => (0, 0),
        };

        let sk_path_pb = keystore_path().map_err(|e| e.to_string())?;
        let sk_path = sk_path_pb.to_string_lossy().to_string();
        let sk_exists = sk_path_pb.exists();
        let sk_len = if sk_exists {
            fs::metadata(&sk_path_pb).ok().map(|m| m.len())
        } else {
            None
        };

        Ok(KemStatus {
            pk_kem_b64_len,
            pk_kem_bytes_len,
            ct_kem_b64_len,
            ct_kem_bytes_len,
            sk_path,
            sk_exists,
            sk_len,
            kem_alg,
        })
    }

    #[derive(serde::Serialize)]
    pub struct MetaRow {
        pub key: String,
        pub value: String,
    }

    #[command]
    pub fn debug_dump_meta(db: State<AppDb>) -> Result<Vec<MetaRow>, String> {
        let conn = db
            .inner()
            .0
            .lock()
            .map_err(|_| "DB lock poisoned".to_string())?;
        let mut stmt = conn
            .prepare("SELECT key, value FROM meta ORDER BY key")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(MetaRow {
                    key: row.get(0)?,
                    value: row.get(1)?,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// Clear keystore file + meta rows (keeps entries table).
    #[command]
    pub fn debug_reset_vault_soft(db: State<AppDb>) -> Result<bool, String> {
        let sk_path = keystore_path().map_err(|e| e.to_string())?;
        remove_file_if_exists(&sk_path).map_err(|e| format!("remove sk: {e}"))?;

        let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM meta WHERE key IN (
            'salt_pw','salt_kdf','kdf','kdf_params','pk_kem','ct_kem','kem_alg','alg'
        )",
            [],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;

        println!("(reset) soft reset done (keystore + meta cleared; entries kept)");
        Ok(true)
    }

    /// Hard reset: soft reset + wipe entries + recreate DB schema via open_and_init.
    #[command]
    pub fn debug_reset_vault_hard(app: AppHandle, db: State<AppDb>) -> Result<bool, String> {
        // 1) soft reset
        debug_reset_vault_soft(db.clone())?;

        // 2) wipe entries table
        {
            let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
            let tx = conn.transaction().map_err(|e| e.to_string())?;
            let _ = tx.execute("DELETE FROM entries", []);
            tx.commit().map_err(|e| e.to_string())?;
        }

        // 3) release file locks
        {
            let mut guard = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
            let tmp = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
            let _old = std::mem::replace(&mut *guard, tmp);
        }

        // 4) delete db file and recreate via open_and_init
        let p = crate::vault_core::db::db_path(&app);
        if p.exists() {
            if let Err(e) = std::fs::remove_file(&p) {
                eprintln!("(reset) failed to remove DB file {}: {}", p.display(), e);
            } else {
                println!("(reset) removed vault database file at {}", p.display());
            }
        } else {
            println!("(reset) db file already missing");
        }

        let new_conn = crate::vault_core::db::open_and_init(&app).map_err(|e| e.to_string())?;
        {
            let mut guard = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
            let _old = std::mem::replace(&mut *guard, new_conn);
        }

        println!(
            "(reset) hard reset done (entries wiped, keystore removed, meta cleared, db recreated)"
        );
        Ok(true)
    }

    // Extra “RAM-only” proof: DB does NOT have key material
    #[derive(serde::Serialize)]
    pub struct NoAesInMeta {
        pub suspicious_keys_found: Vec<String>,
    }

    #[command]
    pub fn debug_check_no_aes_in_meta(db: State<AppDb>) -> Result<NoAesInMeta, String> {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let suspects = ["aes_key", "vault_key", "hkdf", "ikm"];
        let mut found = Vec::new();
        for k in suspects {
            let hit: Option<String> = conn
                .query_row("SELECT value FROM meta WHERE key=?1", [k], |r| r.get(0))
                .optional()
                .map_err(|e| e.to_string())?;
            if hit.is_some() {
                found.push(k.to_string());
            }
        }
        Ok(NoAesInMeta {
            suspicious_keys_found: found,
        })
    }

    // Step 5 self-test: re-derive and report booleans/lengths (RAM-only)
    #[derive(serde::Serialize)]
    pub struct HkdfStep5ZeroizeDemo {
        pub k1_before_b64: String,
        pub k1_after_b64: String,
        pub ss_before_b64: String,
        pub ss_after_b64: String,
        pub ikm_before_len: usize,
        pub ikm_after_all_zero: bool,
        pub aes_before_b64: String,
        pub aes_after_b64: String,
    }

    #[command]
    pub fn debug_hkdf_step5_zeroize_demo(
        db: State<AppDb>,
        master_password: String,
    ) -> Result<HkdfStep5ZeroizeDemo, String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let salt_pw_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='salt_pw'", [], |r| {
                r.get(0)
            })
            .map_err(|_| "salt_pw missing")?;
        let salt_kdf_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='salt_kdf'", [], |r| {
                r.get(0)
            })
            .map_err(|_| "salt_kdf missing")?;

        let salt_pw = B64.decode(&salt_pw_b64).map_err(|_| "salt_pw decode")?;
        let salt_kdf = B64.decode(&salt_kdf_b64).map_err(|_| "salt_kdf decode")?;

        let mut k1 = [0u8; 32];
        pbkdf2_hmac::<Sha256>(master_password.as_bytes(), &salt_pw, 310_000, &mut k1);

        let ss_raw: Vec<u8> = {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
                .map_err(|e| format!("kem new: {e}"))?;
            let (pk, _) = kem.keypair().map_err(|e| format!("keypair: {e}"))?;
            let (_ct, ss) = kem.encapsulate(&pk).map_err(|e| format!("encaps: {e}"))?;
            ss.as_ref().to_vec()
        };

        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(&k1);
        ikm.extend_from_slice(&ss_raw);

        let hk = Hkdf::<Sha256>::new(Some(&salt_kdf), &ikm);
        let mut aes_key = [0u8; 32];
        hk.expand(b"vault-key", &mut aes_key)
            .map_err(|_| "HKDF expand")?;

        let k1_before_b64 = B64.encode(&k1);
        let ss_before_b64 = B64.encode(&ss_raw);
        let ikm_before_len = ikm.len();
        let aes_before_b64 = B64.encode(&aes_key);

        k1.zeroize();
        let mut ss_vec = ss_raw.clone();
        ss_vec.zeroize();
        let ikm_after_all_zero = {
            ikm.zeroize();
            ikm.iter().all(|&b| b == 0)
        };
        aes_key.zeroize();

        let k1_after_b64 = B64.encode(&k1);
        let ss_after_b64 = B64.encode(&ss_vec);
        let aes_after_b64 = B64.encode(&aes_key);

        Ok(HkdfStep5ZeroizeDemo {
            k1_before_b64,
            k1_after_b64,
            ss_before_b64,
            ss_after_b64,
            ikm_before_len,
            ikm_after_all_zero,
            aes_before_b64,
            aes_after_b64,
        })
    }

    #[command]
    pub fn debug_delete_device_key() -> Result<bool, String> {
        match keystore_path() {
            Ok(sk_path) => {
                if sk_path.exists() {
                    std::fs::remove_file(&sk_path)
                        .map_err(|e| format!("Failed to remove device key: {e}"))?;
                    println!("(debug) Removed device key at: {}", sk_path.display());
                    Ok(true)
                } else {
                    Err("Device key already missing".into())
                }
            }
            Err(e) => Err(format!("keystore_path error: {e}")),
        }
    }

    // Print/Assert zeroize demo
    #[derive(serde::Serialize)]
    pub struct ZeroizePrintResult {
        pub k1_len: usize,
        pub ss_len: usize,
        pub ikm_len: usize,
        pub aes_len: usize,
        pub k1_nonzero_before: usize,
        pub ss_nonzero_before: usize,
        pub ikm_nonzero_before: usize,
        pub aes_nonzero_before: usize,
        pub k1_zeroized: bool,
        pub ss_zeroized: bool,
        pub ikm_zeroized: bool,
        pub aes_zeroized: bool,
    }

    fn count_nonzero(bytes: &[u8]) -> usize {
        bytes.iter().filter(|&&b| b != 0).count()
    }

    fn hex4(bytes: &[u8]) -> String {
        let take = bytes.iter().take(4);
        let mut s = String::new();
        for b in take {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    #[command]
    pub fn debug_step5_zeroize_print(
        db: State<AppDb>,
        master_password: String,
    ) -> Result<ZeroizePrintResult, String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        println!("== debug_step5_zeroize_print ==");

        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let salt_pw_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='salt_pw'", [], |r| {
                r.get(0)
            })
            .map_err(|_| "salt_pw missing")?;
        let salt_kdf_b64: String = conn
            .query_row("SELECT value FROM meta WHERE key='salt_kdf'", [], |r| {
                r.get(0)
            })
            .map_err(|_| "salt_kdf missing")?;

        let salt_pw = B64.decode(&salt_pw_b64).map_err(|_| "salt_pw decode")?;
        let salt_kdf = B64.decode(&salt_kdf_b64).map_err(|_| "salt_kdf decode")?;

        let mut k1 = [0u8; 32];
        pbkdf2_hmac::<Sha256>(master_password.as_bytes(), &salt_pw, 310_000, &mut k1);

        let ss_raw: Vec<u8> = {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
                .map_err(|e| format!("kem new: {e}"))?;
            let (pk, _) = kem.keypair().map_err(|e| format!("keypair: {e}"))?;
            let (_ct, ss) = kem.encapsulate(&pk).map_err(|e| format!("encaps: {e}"))?;
            ss.as_ref().to_vec()
        };

        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(&k1);
        ikm.extend_from_slice(&ss_raw);

        let hk = Hkdf::<Sha256>::new(Some(&salt_kdf), &ikm);
        let mut aes_key = [0u8; 32];
        hk.expand(b"vault-key", &mut aes_key)
            .map_err(|_| "HKDF expand failed")?;

        let k1_nonzero_before = count_nonzero(&k1);
        let ss_nonzero_before = count_nonzero(&ss_raw);
        let ikm_nonzero_before = count_nonzero(&ikm);
        let aes_nonzero_before = count_nonzero(&aes_key);
        println!(
            "[before] K1: len=32 nonzero={} preview={}..",
            k1_nonzero_before,
            hex4(&k1)
        );
        println!(
            "[before] SS: len={} nonzero={} preview={}..",
            ss_raw.len(),
            ss_nonzero_before,
            hex4(&ss_raw)
        );
        println!(
            "[before] IKM: len={} nonzero={}",
            ikm.len(),
            ikm_nonzero_before
        );
        println!(
            "[before] AES: len=32 nonzero={} preview={}..",
            aes_nonzero_before,
            hex4(&aes_key)
        );

        k1.zeroize();
        let mut ss_mut = ss_raw.clone();
        ss_mut.zeroize();
        ikm.zeroize();
        aes_key.zeroize();

        let k1_zeroized = k1.iter().all(|&b| b == 0);
        let ss_zeroized = ss_mut.iter().all(|&b| b == 0);
        let ikm_zeroized = ikm.iter().all(|&b| b == 0);
        let aes_zeroized = aes_key.iter().all(|&b| b == 0);

        println!("[after]  K1 zeroized={}", k1_zeroized);
        println!("[after]  SS zeroized={}", ss_zeroized);
        println!("[after]  IKM zeroized={}", ikm_zeroized);
        println!("[after]  AES zeroized={}", aes_zeroized);

        if !(k1_zeroized && ss_zeroized && ikm_zeroized && aes_zeroized) {
            return Err("zeroize check failed (one or more buffers not cleared)".into());
        }

        Ok(ZeroizePrintResult {
            k1_len: 32,
            ss_len: 32,
            ikm_len: 64,
            aes_len: 32,
            k1_nonzero_before,
            ss_nonzero_before,
            ikm_nonzero_before,
            aes_nonzero_before,
            k1_zeroized,
            ss_zeroized,
            ikm_zeroized,
            aes_zeroized,
        })
    }

    // Step 6/7 debug helpers
    #[derive(serde::Serialize)]
    pub struct VaultKeyStatus {
        pub loaded: bool,
    }

    #[command]
    pub fn debug_vault_key_status() -> Result<VaultKeyStatus, String> {
        let guard = VAULT_AES_KEY.read().map_err(|_| "lock poisoned")?;
        Ok(VaultKeyStatus {
            loaded: guard.is_some(),
        })
    }

    #[derive(serde::Serialize)]
    pub struct DbPathInfo {
        pub path: String,
        pub exists: bool,
        pub size: Option<u64>,
    }

    #[command]
    pub fn debug_db_path(app: AppHandle) -> Result<DbPathInfo, String> {
        let p = crate::vault_core::db::db_path(&app);
        let exists = p.exists();
        let size = if exists {
            fs::metadata(&p).ok().map(|m| m.len())
        } else {
            None
        };
        Ok(DbPathInfo {
            path: p.to_string_lossy().to_string(),
            exists,
            size,
        })
    }
    // command to list tables & schemas
    #[derive(serde::Serialize)]
    pub struct ColumnInfo {
        pub cid: i64,
        pub name: String,
        pub r#type: Option<String>,
        pub notnull: bool,
        pub dflt_value: Option<String>,
        pub pk: bool,
    }

    #[derive(serde::Serialize)]
    pub struct TableSchema {
        pub name: String,
        pub sql: Option<String>, // CREATE TABLE ... (may be None for internal tables)
        pub columns: Vec<ColumnInfo>,
    }

    #[command]
    pub fn debug_list_schema(db: State<AppDb>) -> Result<Vec<TableSchema>, String> {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

        // 1) get all tables (user + internal), ordered by name
        let mut stmt = conn
            .prepare("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name")
            .map_err(|e| e.to_string())?;
        let tables = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let sql: Option<String> = row.get(1)?;
                Ok((name, sql))
            })
            .map_err(|e| e.to_string())?;

        let mut out: Vec<TableSchema> = Vec::new();

        for t in tables {
            let (name, sql) = t.map_err(|e| e.to_string())?;

            // 2) columns for each table via PRAGMA table_info(table_name)
            let pragma = format!("PRAGMA table_info({})", name);
            let mut col_stmt = conn.prepare(&pragma).map_err(|e| e.to_string())?;
            let cols_iter = col_stmt
                .query_map([], |row| {
                    // cid, name, type, notnull, dflt_value, pk
                    let cid: i64 = row.get(0)?;
                    let cname: String = row.get(1)?;
                    let ctype: Option<String> = row.get(2)?;
                    let notnull_i: i64 = row.get(3)?;
                    let dflt_value: Option<String> = row.get(4)?;
                    let pk_i: i64 = row.get(5)?;
                    Ok(ColumnInfo {
                        cid,
                        name: cname,
                        r#type: ctype,
                        notnull: notnull_i != 0,
                        dflt_value,
                        pk: pk_i != 0,
                    })
                })
                .map_err(|e| e.to_string())?;

            let mut columns = Vec::new();
            for c in cols_iter {
                columns.push(c.map_err(|e| e.to_string())?);
            }

            out.push(TableSchema { name, sql, columns });
        }

        Ok(out)
    }

    #[command]
    pub fn debug_aes_key_exists() -> bool {
        VAULT_AES_KEY.read().map(|g| g.is_some()).unwrap_or(false)
    }

    #[command]
    pub fn debug_zeroize_aes_key() -> Result<(), String> {
        let guard = VAULT_AES_KEY.read().map_err(|_| "lock poisoned")?;

        if guard.is_none() {
            println!("No AES key stored in RwLock.");
            return Ok(());
        }

        drop(guard);
        println!("AES key found — zeroizing now...");

        zeroize_aes_key().map_err(|e| e.to_string())?;

        let guard_after = VAULT_AES_KEY.read().map_err(|_| "lock poisoned")?;
        println!("Post-wipe AES key state: {:?}", guard_after);

        Ok(())
    }

    // ===================================================================
    // NEW: Debug decapsulation status (no secret returned)
    // ===================================================================

    #[derive(serde::Serialize)]
    pub struct DecapStatus {
        pub sk_path: String,
        pub sk_exists: bool,
        pub ct_kem_len: usize,
        pub ss_len: usize,
        pub ok: bool,
    }

    /// Debug helper: run decapsulation and report sizes/status, but never return the secret.
    #[command]
    pub fn debug_decapsulate_status(db: State<AppDb>) -> Result<DecapStatus, String> {
        // info for reporting
        let sk_path = keystore_path().map_err(|e| e.to_string())?;
        let sk_exists = sk_path.exists();

        // ct_kem length (decoded)
        let ct_kem_len = {
            let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
            let ct_b64: Option<String> = conn
                .query_row("SELECT value FROM meta WHERE key='ct_kem'", [], |r| {
                    r.get::<_, String>(0)
                })
                .optional()
                .map_err(|e| e.to_string())?;
            match ct_b64 {
                Some(s) => B64.decode(s.as_bytes()).map(|v| v.len()).unwrap_or(0),
                None => 0,
            }
        };

        // Attempt decapsulation (does NOT expose the secret)
        match recover_device_secret(&db) {
            Ok(ss) => {
                let ss_len = ss.len();
                let mut ss_zero = ss;
                ss_zero.zeroize();
                Ok(DecapStatus {
                    sk_path: sk_path.to_string_lossy().to_string(),
                    sk_exists,
                    ct_kem_len,
                    ss_len,
                    ok: true,
                })
            }
            Err(e) => Err(e),
        }
    }

    // ===============================
    // Debug Helpers for Step 2 part 5
    // ==============================

    #[derive(serde::Serialize)]
    pub struct EntryBlobInfo {
        pub id: i64,
        pub nonce_len: usize,
        pub tag_len: usize,
        pub ct_len: usize,
        pub nonce_hex: String,
        pub tag_hex: String,
        pub ct_hex_prefix: String,
        pub is_ct_mostly_printable: bool,
    }
    fn hex(bytes: &[u8], max: usize) -> String {
        let mut s = String::new();
        for b in bytes.iter().take(max) {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }
    // Checks if text is readable and therefore not encrypted
    fn mostly_printable(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let printable = bytes
            .iter()
            .filter(|&&b| (b >= 0x20 && b <= 0x7e) || b == b'\n')
            .count();
        (printable as f32) / (bytes.len() as f32) > 0.9
    }

    // report lengths + tiny hex previews of an entry’s nonce, ciphertext, tag to verify AES-GCM storage
    #[command]
    pub fn debug_entry_blob_info(db: State<AppDb>, id: i64) -> Result<EntryBlobInfo, String> {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let (nonce, ct, tag): (Vec<u8>, Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT nonce, ciphertext, tag FROM entries WHERE id=?1",
                rusqlite::params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| e.to_string())?;
        Ok(EntryBlobInfo {
            id,
            nonce_len: nonce.len(),
            tag_len: tag.len(),
            ct_len: ct.len(),
            nonce_hex: hex(&nonce, 12),
            tag_hex: hex(&tag, 16),
            ct_hex_prefix: hex(&ct, 16),
            is_ct_mostly_printable: mostly_printable(&ct),
        })
    }
    // Flips one byte in entry values to test AES_GCM tamper detection
    #[command]
    pub fn debug_tamper_entry(
        db: State<AppDb>,
        id: i64,
        field: String,
        index: Option<i64>, // flips byte 0 by default
        xor: u8,            // bit mask
    ) -> Result<usize, String> {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let col = match field.as_str() {
            // which columns to corrupt
            "ciphertext" => "ciphertext",
            "tag" => "tag",
            "nonce" => "nonce",
            other => return Err(format!("unknown field: {}", other)),
        };
        let mut blob: Vec<u8> = conn
            .query_row(
                &format!("SELECT {} FROM entries WHERE id=?1", col),
                rusqlite::params![id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if blob.is_empty() {
            return Err("blob empty".into());
        }
        let i = index.unwrap_or(0) as usize;
        if i >= blob.len() {
            return Err(format!("index {} out of range {}", i, blob.len()));
        }
        blob[i] ^= xor;
        let n = conn
            .execute(
                &format!("UPDATE entries SET {}=?1 WHERE id=?2", col),
                rusqlite::params![blob, id],
            )
            .map_err(|e| e.to_string())?;
        Ok(n)
    }

    #[derive(serde::Serialize)]
    pub struct CryptoSelfTest {
        pub nonce_len: usize,
        pub tag_len: usize,
        pub roundtrip_ok: bool,
    }

    #[command]
    pub fn debug_crypto_selftest(pt: String) -> Result<CryptoSelfTest, String> {
        let guard = get_aes_key_ref().map_err(|_| "Vault is locked — unlock first")?;
        let k = guard.as_ref().ok_or("Vault is locked — unlock first")?;
        let sealed = encrypt_password(k, &pt)?;
        // let out = decrypt_password(k, &sealed.nonce, sealed.ciphertext, &sealed.tag)?;
        let out = "";
        Ok(CryptoSelfTest {
            nonce_len: sealed.nonce.len(),
            tag_len: sealed.tag.len(),
            roundtrip_ok: out == pt,
        })
    }
}

#[cfg(debug_assertions)]
pub use debug_commands::*;

// =========================
// Vault CRUD (placeholder crypto for now)
// =========================

fn validate_label(label: &str) -> Result<String, String> {
    let trimmed_label = label.trim();
    if trimmed_label.is_empty() {
        return Err("Label is required".into());
    }
    if trimmed_label.len() > 128 {
        return Err("Label is too long (max 128)".into());
    }
    Ok(trimmed_label.to_string())
}

fn validate_username(username: &str) -> Result<String, String> {
    let trimmed_username = username.trim();
    if trimmed_username.is_empty() {
        return Err("Username is required".into());
    }
    if trimmed_username.len() > 256 {
        return Err("Username is too long (max 256)".into());
    }
    Ok(trimmed_username.to_string())
}

fn validate_password(password: String) -> Result<SecretString, String> {
    if password.is_empty() {
        return Err("Password is required".into());
    }
    if password.len() > 10000 {
        return Err("Password is too long".into());
    }
    Ok(SecretString::from(password))
}

fn validate_notes(opt: &Option<String>) -> Result<Option<String>, String> {
    if let Some(notes) = opt {
        let trimmed_notes = notes.trim();
        if trimmed_notes.len() > 2_000 {
            return Err("Notes are too long (max 2000)".into());
        }
        if trimmed_notes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed_notes.to_string()))
        }
    } else {
        Ok(None)
    }
}

#[command]
pub fn vault_list(db: State<AppDb>) -> Result<Vec<EntryListItem>, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    db::list_entries(&conn).map_err(|e| e.to_string())
}

#[command]
pub fn vault_add(
    db: State<AppDb>,
    label: String,
    username: String,
    password: String,
    notes: Option<String>,
) -> Result<EntryListItem, String> {
    let label = validate_label(&label)?;
    let username = validate_username(&username)?;
    let password = validate_password(password)?;
    let notes = validate_notes(&notes)?;

    // Uses VAULT_AES_KEY by reference
    let sealed = {
        let guard = get_aes_key_ref().map_err(|_| "Vault is locked — unlock first")?;
        let aes_key_ref = guard.as_ref().ok_or("Vault is locked — unlock first")?;
        encrypt_password(aes_key_ref, password.expose_secret())?
    };

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let new = NewEntry {
        label: &label,
        username: &username,
        notes: notes.as_deref(),
        nonce: &sealed.nonce,
        ciphertext: &sealed.ciphertext,
        tag: &sealed.tag,
    };
    db::add_entry(&conn, new).map_err(|e| e.to_string())
}

#[command]
pub fn vault_get(db: State<AppDb>, id: i64) -> Result<String, String> {
    if id <= 0 {
        return Err("Invalid id".into());
    }

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let enc = crate::vault_core::db::get_entry_encrypted(&conn, id)
        .map_err(|e| e.to_string())?
        .ok_or("No entry found with that id")?;

    if enc.nonce.len() != 12 || enc.tag.len() != 16 {
        return Err("Entry is corrupt (invalid nonce/tag size)".into());
    }
    let mut nonce12 = [0u8; 12];
    nonce12.copy_from_slice(&enc.nonce);
    let mut tag16 = [0u8; 16];
    tag16.copy_from_slice(&enc.tag);

    // VAULT_AES_KEY passed by reference
    let plaintext = {
        let guard = get_aes_key_ref().map_err(|_| "Vault is locked — unlock first")?;
        let aes_key_ref = guard.as_ref().ok_or("Vault is locked — unlock first")?;
        let secret = decrypt_password(aes_key_ref, &nonce12, enc.ciphertext, &tag16)?;
        secret.expose_secret().to_string()
    };

    nonce12.zeroize();
    tag16.zeroize();

    Ok(plaintext)
}

#[command]
pub fn vault_delete(db: State<AppDb>, id: i64) -> Result<(), String> {
    if id <= 0 {
        return Err("Invalid id".into());
    }
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let n = db::delete_entry(&conn, id).map_err(|e| e.to_string())?;
    if n == 0 {
        Err("No entry found with that id".into())
    } else {
        Ok(())
    }
}

/// DEV ONLY: Insert a known-corrupted entry (same values every time).
/// Always returns the inserted entry id.
/// Intended to trigger AES-GCM decrypt failure in `vault_get`.
#[cfg(debug_assertions)]
#[command]
pub fn debug_insert_bad_entry(db: State<AppDb>) -> Result<i64, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // Known wrong nonce + tag + ciphertext (invalid AES-GCM)
    let nonce: [u8; 12] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let tag: [u8; 16] = [
        0xBA, 0xAD, 0xF0, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let ciphertext: Vec<u8> = vec![0x00, 0x11, 0x22, 0x33];

    let new = crate::vault_core::db::NewEntry {
        label: "CorruptEntry",
        username: "testuser",
        notes: None,
        nonce: &nonce,
        ciphertext: &ciphertext,
        tag: &tag,
    };

    let inserted = crate::vault_core::db::add_entry(&conn, new).map_err(|e| e.to_string())?;

    println!("[debug] inserted corrupted entry id={} ✅", inserted.id);

    Ok(inserted.id)
}

// debug vault corruption
/// Debug helper: intentionally corrupt one of the manifest-dependent fields
/// to trigger "tampered vault" detection during next unlock.
/// This simulates external modification of the vault database.
#[cfg(debug_assertions)]
#[command]
pub fn debug_corrupt_manifest(db: State<AppDb>) -> Result<bool, String> {
    use rand::Rng;

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // picking a field that is in the manifest hash
    // salt_kdf is safe to corrupt (will not break DB structure)
    let key_to_corrupt = "salt_kdf";

    // read original value
    let original_value: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key=?1",
            [key_to_corrupt],
            |r| r.get(0),
        )
        .map_err(|_| format!("missing meta key: {key_to_corrupt}"))?;

    // mutate a single random character to simulate tampering
    let mut chars: Vec<char> = original_value.chars().collect();
    if !chars.is_empty() {
        let mut rng = rand::rng();
        let i = rng.random_range(0..chars.len());
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' }; // flip a char
    }
    let corrupted: String = chars.into_iter().collect();

    // update the field in DB
    conn.execute(
        "UPDATE meta SET value=?1 WHERE key=?2",
        (&corrupted, &key_to_corrupt),
    )
    .map_err(|e| format!("failed to update meta: {e}"))?;

    println!(
        "(debug) intentionally corrupted '{}' field — manifest mismatch expected next unlock",
        key_to_corrupt
    );

    Ok(true)
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod tests;
