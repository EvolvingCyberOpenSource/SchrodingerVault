use tauri::{command, State};
use rusqlite::{params, OptionalExtension};
use crate::state::AppDb;

use rand::{rng, RngCore}; // rand 0.9: rng() + RngCore::fill_bytes
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

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

    // Device KEM keypair + self-encapsulation
    let (pk_kem_raw, ct_kem_raw) = generate_device_keypair().map_err(|e| e.to_string())?;
    println!(
        "(debug) pk_kem_bytes_len={}, ct_kem_bytes_len={}",
        pk_kem_raw.len(), ct_kem_raw.len()
    );

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

    // Zeroize K1 (good hygiene; you’ll HKDF it later)
    k1.zeroize();

    println!("(debug) salts + kdf + kem public material stored; SK on disk.");
    println!("== create_vault done ==");
    Ok(true)
}

/// Generates ML-KEM-768 keypair, encapsulates, self-checks decapsulation,
/// writes SK to keystore with tight perms, and returns (pk_raw, ct_raw).
fn generate_device_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
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

    // Return raw pk/ct bytes for DB storage (as Base64)
    Ok((pk_kem.as_ref().to_vec(), ct_kem.as_ref().to_vec()))
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

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
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

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    // If your table is named differently, change this.
    let _ = tx.execute("DELETE FROM entries", []);
    tx.commit().map_err(|e| e.to_string())?;

    println!("(reset) hard reset done (entries wiped)");
    Ok(true)
}
