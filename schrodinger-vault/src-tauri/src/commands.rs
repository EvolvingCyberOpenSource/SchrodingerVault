use tauri::{command, State};
use rusqlite::{params, OptionalExtension};
use crate::state::AppDb;

use rand::{rng, RngCore}; // rand 0.9: rng() + RngCore::fill_bytes
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use hkdf::Hkdf;

use oqs; // high-level, safe wrappers
use std::{fs, io, path::{Path, PathBuf}};
use std::fs::OpenOptions;
use std::io::Write;
use zeroize::Zeroize;
use dirs;

// ============================ Utilities ============================

/// Write a secret key file with tight permissions:
/// - Unix/macOS: 0600
/// - Windows: in %LOCALAPPDATA% (per-user ACLs)
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
        // ensure final perms are exactly 0600
        let mut p = f.metadata()?.permissions();
        p.set_mode(0o600);
        fs::set_permissions(path, p)?;
        Ok(())
    }

    #[cfg(windows)]
    {
        // In %LOCALAPPDATA%, new files inherit a per-user ACL (private to the account).
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

// ============================ Examples / Scaffolding ============================

#[command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[derive(serde::Serialize)]
pub struct Person { pub id: i32, pub name: String }

#[command]
pub fn add_person(db: State<AppDb>, name: String) -> Result<(), String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    conn.execute("INSERT INTO person (name, data) VALUES (?1, NULL)", params![name])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[command]
pub fn user_exists(db: State<AppDb>) -> Result<bool, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let count: i64 = conn
        .query_row("SELECT COUNT(1) FROM user WHERE id = 1", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    Ok(count > 0)
}

#[command]
pub fn list_people(db: State<AppDb>) -> Result<Vec<Person>, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let mut stmt = conn.prepare("SELECT id, name FROM person ORDER BY id")
        .map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        Ok(Person { id: row.get(0)?, name: row.get(1)? })
    }).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for r in rows { out.push(r.map_err(|e| e.to_string())?); }
    Ok(out)
}

// ============================ Vault Init ============================

#[command]
pub fn create_vault(db: State<AppDb>, master_password: String) -> Result<bool, String> {
    println!("== create_vault ==");
    println!("(debug) received password len = {}", master_password.len());

    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // salts (random)
    let mut r = rng();
    let mut salt_pw  = [0u8; 16];
    let mut salt_kdf = [0u8; 32];
    r.fill_bytes(&mut salt_pw);
    r.fill_bytes(&mut salt_kdf);

    // Base64 for TEXT storage
    let salt_pw_b64  = B64.encode(salt_pw);
    let salt_kdf_b64 = B64.encode(salt_kdf);

    // PBKDF2 params
    let kdf = "pbkdf2-hmac-sha256";
    let kdf_params = r#"{"iterations":310000,"out":32,"algo":"sha256"}"#;

    // PBKDF2 derive K1 (RAM only)
    let iterations: u32 = 310_000;
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password.as_bytes(), &salt_pw, iterations.into(), &mut k1);
    println!("(debug) PBKDF2 derived K1 (32 bytes in RAM)");

    // Device KEM keypair + self-encapsulation (returns pk, ct, ss)
    let (pk_kem_raw, ct_kem_raw, mut ss_buf) = generate_device_keypair()
        .map_err(|e| e.to_string())?;
    println!(
        "(debug) pk_kem_bytes_len={}, ct_kem_bytes_len={}, ss_len={}",
        pk_kem_raw.len(), ct_kem_raw.len(), ss_buf.len()
    );

    // Step 5: Blend K1 and ss via HKDF-SHA256:
    // IKM = K1 || ss, salt = salt_kdf, info = "vault-key", out_len = 32 (AES-256)
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&k1);
    ikm.extend_from_slice(&ss_buf);

    let hk = Hkdf::<Sha256>::new(Some(&salt_kdf), &ikm);
    let mut aes_key = [0u8; 32];
    hk.expand(b"vault-key", &mut aes_key)
        .map_err(|_| "HKDF expand failed")?;
    println!("(debug) derived AES-256 key (32 bytes) in RAM");

    // Zeroize sensitive inputs immediately
    k1.zeroize();
    ss_buf.zeroize();
    ikm.zeroize();
    aes_key.zeroize();

    // Base64 for TEXT meta
    let pk_kem_b64 = B64.encode(&pk_kem_raw);
    let ct_kem_b64 = B64.encode(&ct_kem_raw);
    let kem_alg = "ML-KEM-768";

    // Store public/metadata only
    {
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (&"salt_pw",  &salt_pw_b64)).map_err(|e| e.to_string())?;
        tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (&"salt_kdf", &salt_kdf_b64)).map_err(|e| e.to_string())?;
        tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (&"kdf", kdf)).map_err(|e| e.to_string())?;
        tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (&"kdf_params", kdf_params)).map_err(|e| e.to_string())?;

        tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (&"pk_kem", &pk_kem_b64)).map_err(|e| e.to_string())?;
        tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (&"ct_kem", &ct_kem_b64)).map_err(|e| e.to_string())?;
        tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (&"kem_alg", kem_alg)).map_err(|e| e.to_string())?;

        tx.commit().map_err(|e| e.to_string())?;
    }

    // K1/ss/AES key never persisted; only public data saved.
    println!("(debug) salts + kdf + kem public material stored; SK on disk.");
    println!("== create_vault done ==");
    Ok(true)
}

/// Generates ML-KEM-768 keypair, encapsulates, self-checks decapsulation,
/// writes SK to keystore with tight perms, and returns (pk_raw, ct_raw, ss).
fn generate_device_keypair() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    oqs::init();

    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
        .map_err(|e| format!("kem new: {e}"))?;

    let (pk_kem, sk_kem) = kem.keypair()
        .map_err(|e| format!("keypair: {e}"))?;
    println!("(debug) generated ML-KEM-768 keypair: pk={}B, sk={}B",
        pk_kem.as_ref().len(), sk_kem.as_ref().len());

    let (ct_kem, ss_raw) = kem.encapsulate(&pk_kem)
        .map_err(|e| format!("encapsulate: {e}"))?;
    let ss2 = kem.decapsulate(&sk_kem, &ct_kem)
        .map_err(|e| format!("decapsulate: {e}"))?;

    if ss_raw.as_ref() == ss2.as_ref() {
        println!("(debug) shared secret match ({} bytes)", ss_raw.len());
    } else {
        println!("(debug) ERROR: shared secret mismatch!");
    }

    // Write SK securely to app-private keystore
    let sk_path = keystore_path().map_err(|e| format!("keystore_path: {e}"))?;
    write_secret_key_secure(&sk_path, sk_kem.as_ref())
        .map_err(|e| format!("write sk: {e}"))?;
    println!("(debug) wrote secret key to: {}", sk_path.to_string_lossy());

    // Return raw pk/ct bytes + ss (RAM-only; caller will zeroize ss)
    Ok((
        pk_kem.as_ref().to_vec(),
        ct_kem.as_ref().to_vec(),
        ss_raw.as_ref().to_vec(),
    ))
}

// ============================ Debug / Demo Helpers ============================

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
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned".to_string())?;

    let pk_b64: Option<String> = conn.query_row(
        "SELECT value FROM meta WHERE key = 'pk_kem'", [], |r| r.get(0)
    ).optional().map_err(|e| e.to_string())?;

    let ct_b64: Option<String> = conn.query_row(
        "SELECT value FROM meta WHERE key = 'ct_kem'", [], |r| r.get(0)
    ).optional().map_err(|e| e.to_string())?;

    let kem_alg: Option<String> = conn.query_row(
        "SELECT value FROM meta WHERE key = 'kem_alg'", [], |r| r.get(0)
    ).optional().map_err(|e| e.to_string())?;

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
    let sk_len = if sk_exists { fs::metadata(&sk_path_pb).ok().map(|m| m.len()) } else { None };

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
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned".to_string())?;
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

fn remove_file_if_exists(p: &Path) -> io::Result<()> {
    match fs::remove_file(p) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Clear keystore file + meta rows (keeps entries table).
#[command]
pub fn debug_reset_vault_soft(db: State<AppDb>) -> Result<bool, String> {
    let sk_path = keystore_path().map_err(|e| e.to_string())?;
    remove_file_if_exists(&sk_path).map_err(|e| format!("remove sk: {e}"))?;

    // make this mutable ↓↓↓
    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM meta WHERE key IN (
            'salt_pw','salt_kdf','kdf','kdf_params','pk_kem','ct_kem','kem_alg'
        )",
        [],
    ).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    println!("(reset) soft reset done (keystore + meta cleared; entries kept)");
    Ok(true)
}

/// Do soft reset AND wipe entries table (if present).
#[command]
pub fn debug_reset_vault_hard(db: State<AppDb>) -> Result<bool, String> {
    debug_reset_vault_soft(db.clone())?;

    // make this mutable ↓↓↓
    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let _ = tx.execute("DELETE FROM entries", []);
    tx.commit().map_err(|e| e.to_string())?;

    println!("(reset) hard reset done (entries wiped)");
    Ok(true)
}

#[derive(serde::Serialize)]
pub struct NoAesInMeta {
    pub suspicious_keys_found: Vec<String>,
}

/// Convenience check that your meta table does not hold AES/HKDF material.
/// Returns the list of suspicious keys it found (usually empty).
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
    Ok(NoAesInMeta { suspicious_keys_found: found })
}

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

/// Demo helper: derive K1 and ss, blend with HKDF, show Base64 before/after zeroize.
/// For demo only — do not keep in production.
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
    // tiny, redacted preview of the first 4 bytes for visual confirmation
    let take = bytes.iter().take(4);
    let mut s = String::new();
    for b in take { use std::fmt::Write; let _ = write!(s, "{:02x}", b); }
    s
}

/// Prints before/after status around Step 5 zeroization; asserts (returns Err) if any buffer
/// is not fully zeroized afterwards. For demo only.
#[command]
pub fn debug_step5_zeroize_print(db: State<AppDb>, master_password: String) -> Result<ZeroizePrintResult, String> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    println!("== debug_step5_zeroize_print ==");

    // load salts from DB
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let salt_pw_b64: String = conn.query_row(
        "SELECT value FROM meta WHERE key='salt_pw'", [], |r| r.get(0)
    ).map_err(|_| "salt_pw missing")?;
    let salt_kdf_b64: String = conn.query_row(
        "SELECT value FROM meta WHERE key='salt_kdf'", [], |r| r.get(0)
    ).map_err(|_| "salt_kdf missing")?;

    let salt_pw = B64.decode(&salt_pw_b64).map_err(|_| "salt_pw decode")?;
    let salt_kdf = B64.decode(&salt_kdf_b64).map_err(|_| "salt_kdf decode")?;

    // derive K1 (RAM only)
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password.as_bytes(), &salt_pw, 310_000, &mut k1);

    // obtain ss
    // Path A: FFI decapsulation using stored ct+sk (enable with --features ffi-decap)
    #[cfg(feature = "ffi-decap")]
    let ss_raw: Vec<u8> = {
        use oqs_sys as oqsffi;
        let ct_b64: String = conn.query_row(
            "SELECT value FROM meta WHERE key='ct_kem'", [], |r| r.get(0)
        ).map_err(|_| "ct_kem missing")?;
        let ct_bytes = B64.decode(&ct_b64).map_err(|_| "ct_kem decode")?;
        let sk_path = keystore_path().map_err(|e| e.to_string())?;
        let sk_bytes = std::fs::read(&sk_path).map_err(|_| "sk missing")?;
        unsafe {
            let kem = oqsffi::kem::OQS_KEM_ml_kem_768_new();
            if kem.is_null() { return Err("ffi kem new failed".into()); }
            let mut ss = vec![0u8; 32];
            let rc = oqsffi::kem::OQS_KEM_decaps(
                kem,
                ss.as_mut_ptr(),
                ct_bytes.as_ptr(),
                sk_bytes.as_ptr()
            );
            oqsffi::kem::OQS_KEM_free(kem);
            if rc != oqsffi::common::OQS_STATUS_OQS_SUCCESS {
                return Err("ffi decapsulation failed".into());
            }
            ss
        }
    };

    // Path B: fallback (no FFI) — make an ephemeral keypair and encapsulate
    #[cfg(not(feature = "ffi-decap"))]
    let ss_raw: Vec<u8> = {
        oqs::init();
        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
            .map_err(|e| format!("kem new: {e}"))?;
        let (pk, _) = kem.keypair().map_err(|e| format!("keypair: {e}"))?;
        let (_ct, ss) = kem.encapsulate(&pk).map_err(|e| format!("encaps: {e}"))?;
        ss.as_ref().to_vec()
    };

    // IKM = K1 || ss
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&k1);
    ikm.extend_from_slice(&ss_raw);

    // HKDF -> AES-256 key (RAM only)
    let hk = Hkdf::<Sha256>::new(Some(&salt_kdf), &ikm);
    let mut aes_key = [0u8; 32];
    hk.expand(b"vault-key", &mut aes_key).map_err(|_| "HKDF expand failed")?;

    // BEFORE: print non-secret diagnostics (lengths + nonzero counts + tiny preview)
    let k1_nonzero_before  = count_nonzero(&k1);
    let ss_nonzero_before  = count_nonzero(&ss_raw);
    let ikm_nonzero_before = count_nonzero(&ikm);
    let aes_nonzero_before = count_nonzero(&aes_key);
    println!("[before] K1: len=32 nonzero={} preview={}..", k1_nonzero_before, hex4(&k1));
    println!("[before] SS: len={} nonzero={} preview={}..", ss_raw.len(), ss_nonzero_before, hex4(&ss_raw));
    println!("[before] IKM: len={} nonzero={}", ikm.len(), ikm_nonzero_before);
    println!("[before] AES: len=32 nonzero={} preview={}..", aes_nonzero_before, hex4(&aes_key));

    // ZEROIZE
    k1.zeroize();
    let mut ss_mut = ss_raw.clone();
    ss_mut.zeroize();
    ikm.zeroize();
    aes_key.zeroize();

    // AFTER: verify zeroization
    let k1_zeroized  = k1.iter().all(|&b| b == 0);
    let ss_zeroized  = ss_mut.iter().all(|&b| b == 0);
    let ikm_zeroized = ikm.iter().all(|&b| b == 0);
    let aes_zeroized = aes_key.iter().all(|&b| b == 0);

    println!("[after]  K1 zeroized={}", k1_zeroized);
    println!("[after]  SS zeroized={}", ss_zeroized);
    println!("[after]  IKM zeroized={}", ikm_zeroized);
    println!("[after]  AES zeroized={}", aes_zeroized);

    // Hard fail if any didn’t zeroize (handy during demo)
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
