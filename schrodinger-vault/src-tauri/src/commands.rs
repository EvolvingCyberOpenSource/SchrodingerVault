use tauri::{command, AppHandle, State};
use rusqlite::{params, OptionalExtension};
use crate::state::AppDb;
use crate::vault_core::db::{self, EntryListItem, NewEntry};

use rand::{rng, RngCore}; // rand 0.9: rng() + RngCore::fill_bytes (reserved for future nonce use)
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use hkdf::Hkdf;

use oqs; // high-level, safe wrappers
use std::{fs, io, path::{Path, PathBuf}};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::OnceLock; // hold AES_KEY in RAM for the session
use zeroize::Zeroize;
use dirs;
use secrecy::{SecretString, ExposeSecret};

// =========================
// Session AES key (RAM-only)
// =========================

static VAULT_AES_KEY: OnceLock<[u8; 32]> = OnceLock::new();

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

// =========================
// Demo / examples
// =========================

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

// =========================
// Vault creation (Step 5–7)
// DB schema is created by vault_core::db::open_and_init in main.rs setup
// =========================

#[command]
pub fn create_vault(_app: AppHandle, db: State<AppDb>, master_password: String) -> Result<bool, String> {
    let master_password = SecretString::from(master_password);
    println!("== create_vault ==");
    println!("(debug) received password len = {}", master_password.expose_secret().len());

    // Use the live, already-initialized connection
    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // salts (random)
    let mut r = rng();
    let mut salt_pw  = [0u8; 32];
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
    pbkdf2_hmac::<Sha256>(master_password.expose_secret().as_bytes(), &salt_pw, iterations.into(), &mut k1);
    println!("(debug) PBKDF2 derived K1 (32 bytes in RAM)");

    // Device KEM keypair + self-encapsulation (returns pk, ct, ss)
    let (pk_kem_raw, ct_kem_raw, mut ss_buf) = generate_device_keypair()
        .map_err(|e| e.to_string())?;
    println!(
        "(debug) pk_kem_bytes_len={}, ct_kem_bytes_len={}, ss_len={}",
        pk_kem_raw.len(), ct_kem_raw.len(), ss_buf.len()
    );

    // Step 5: Blend K1 and ss via HKDF-SHA256:
    // HKDF-Extract with K1
    let hk_k1 = Hkdf::<Sha256>::new(Some(&salt_kdf), &k1);
    let mut prk1 = [0u8; 32];
    hk_k1.expand(&[], &mut prk1).map_err(|e| e.to_string())?;

    // HKDF-Extract again with ss, using prk1 as salt
    let hk_final = Hkdf::<Sha256>::new(Some(&prk1), &ss_buf);

    // Expand to AES key
    let mut aes_key_tmp = [0u8; 32];
    hk_final.expand(b"vault-key", &mut aes_key_tmp).map_err(|_| "HKDF expand failed")?;
    println!("(debug) derived AES-256 key (32 bytes) in RAM");

    // Install AES key into process RAM for this session.
    let _ = VAULT_AES_KEY.set(aes_key_tmp);

    // Zeroize sensitive inputs immediately (K1, ss, IKM only; AES stays in RAM)
    k1.zeroize();
    ss_buf.zeroize();
    prk1.zeroize();

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

        // algorithm label string for the vault (public)
        let alg = "mlkem768|aes256gcm|hkdfsha256|pbkdf2";
        tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (&"alg", alg))
          .map_err(|e| e.to_string())?;

        tx.commit().map_err(|e| e.to_string())?;
    }

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

    Ok((
        pk_kem.as_ref().to_vec(),
        ct_kem.as_ref().to_vec(),
        ss_raw.as_ref().to_vec(),
    ))
}

// =========================
// Debug helpers
// =========================

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

    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM meta WHERE key IN (
            'salt_pw','salt_kdf','kdf','kdf_params','pk_kem','ct_kem','kem_alg','alg'
        )",
        [],
    ).map_err(|e| e.to_string())?;
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

    println!("(reset) hard reset done (entries wiped, keystore removed, meta cleared, db recreated)");
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
    Ok(NoAesInMeta { suspicious_keys_found: found })
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
    master_password: String
) -> Result<HkdfStep5ZeroizeDemo, String> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let salt_pw_b64: String = conn.query_row(
        "SELECT value FROM meta WHERE key='salt_pw'", [], |r| r.get(0)
    ).map_err(|_| "salt_pw missing")?;
    let salt_kdf_b64: String = conn.query_row(
        "SELECT value FROM meta WHERE key='salt_kdf'", [], |r| r.get(0)
    ).map_err(|_| "salt_kdf missing")?;

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
    hk.expand(b"vault-key", &mut aes_key).map_err(|_| "HKDF expand")?;

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
    for b in take { use std::fmt::Write; let _ = write!(s, "{:02x}", b); }
    s
}

#[command]
pub fn debug_step5_zeroize_print(db: State<AppDb>, master_password: String) -> Result<ZeroizePrintResult, String> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    println!("== debug_step5_zeroize_print ==");

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let salt_pw_b64: String = conn.query_row(
        "SELECT value FROM meta WHERE key='salt_pw'", [], |r| r.get(0)
    ).map_err(|_| "salt_pw missing")?;
    let salt_kdf_b64: String = conn.query_row(
        "SELECT value FROM meta WHERE key='salt_kdf'", [], |r| r.get(0)
    ).map_err(|_| "salt_kdf missing")?;

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
    hk.expand(b"vault-key", &mut aes_key).map_err(|_| "HKDF expand failed")?;

    let k1_nonzero_before  = count_nonzero(&k1);
    let ss_nonzero_before  = count_nonzero(&ss_raw);
    let ikm_nonzero_before = count_nonzero(&ikm);
    let aes_nonzero_before = count_nonzero(&aes_key);
    println!("[before] K1: len=32 nonzero={} preview={}..", k1_nonzero_before, hex4(&k1));
    println!("[before] SS: len={} nonzero={} preview={}..", ss_raw.len(), ss_nonzero_before, hex4(&ss_raw));
    println!("[before] IKM: len={} nonzero={}", ikm.len(), ikm_nonzero_before);
    println!("[before] AES: len=32 nonzero={} preview={}..", aes_nonzero_before, hex4(&aes_key));

    k1.zeroize();
    let mut ss_mut = ss_raw.clone();
    ss_mut.zeroize();
    ikm.zeroize();
    aes_key.zeroize();

    let k1_zeroized  = k1.iter().all(|&b| b == 0);
    let ss_zeroized  = ss_mut.iter().all(|&b| b == 0);
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
pub struct VaultKeyStatus { pub loaded: bool }

#[command]
pub fn debug_vault_key_status() -> Result<VaultKeyStatus, String> {
    Ok(VaultKeyStatus { loaded: VAULT_AES_KEY.get().is_some() })
}

#[derive(serde::Serialize)]
pub struct DbPathInfo { pub path: String, pub exists: bool, pub size: Option<u64> }

#[command]
pub fn debug_db_path(app: AppHandle) -> Result<DbPathInfo, String> {
    let p = crate::vault_core::db::db_path(&app);
    let exists = p.exists();
    let size = if exists { fs::metadata(&p).ok().map(|m| m.len()) } else { None };
    Ok(DbPathInfo { path: p.to_string_lossy().to_string(), exists, size })
}

// =========================
// Vault CRUD (placeholder crypto for now)
// =========================

fn validate_label(label: &str) -> Result<String, String> {
    let trimmed_label = label.trim();
    if trimmed_label.is_empty() { return Err("Label is required".into()); }
    if trimmed_label.len() > 128 { return Err("Label is too long (max 128)".into()); }
    Ok(trimmed_label.to_string())
}

fn validate_username(username: &str) -> Result<String, String> {
    let trimmed_username = username.trim();
    if trimmed_username.is_empty() { return Err("Username is required".into()); }
    if trimmed_username.len() > 256 { return Err("Username is too long (max 256)".into()); }
    Ok(trimmed_username.to_string())
}

fn validate_password(password: &str) -> Result<String, String> {
    if password.is_empty() { return Err("Password is required".into()); }
    if password.len() > 10000 { return Err("Password is too long".into()); }
    Ok(password.to_string())
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
    let password = validate_password(&password)?;
    let notes = validate_notes(&notes)?;

    // TODO: Replace with real AES-256-GCM using VAULT_AES_KEY and a 12-byte random nonce.
    // TEMP placeholder: nonce all-zero, ciphertext = plaintext password bytes
    let nonce = [0u8; 12];
    let ciphertext_bytes = password.into_bytes();

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let new = NewEntry {
        label: &label,
        username: &username,
        notes: notes.as_deref(),
        nonce: &nonce,
        ciphertext: &ciphertext_bytes,
    };
    db::add_entry(&conn, new).map_err(|e| e.to_string())
}

#[command]
pub fn vault_get(db: State<AppDb>, id: i64) -> Result<String, String> {
    if id <= 0 {
        return Err("Invalid id".into());
    }
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    match db::temp_get_ciphertext(&conn, id) {
        Ok(Some(secret)) => Ok(secret),
        Ok(None) => Err("No entry found with that id".into()),
        Err(e) => Err(e.to_string()),
    }
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
