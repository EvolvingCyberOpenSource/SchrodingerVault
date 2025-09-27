use tauri::{command, State};
use rusqlite::{params, OptionalExtension};
use crate::state::AppDb;

use rand::RngCore;        // for .fill_bytes()
use rand::rng;            // rand 0.9: use rng() instead of deprecated thread_rng()

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use oqs; // high-level oqs (safe wrapper)
use std::{fs, path::PathBuf, io};
use zeroize::Zeroize;
use dirs; // per-user data dir

// Secure write helper: ensures SK file is 0600 on Unix; user-private on Windows.
use std::path::Path;
use std::fs::OpenOptions;
use std::io::Write;

fn write_secret_key_secure(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        // Create atomically with 0600
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        // Ensure final perms are 0600
        let mut p = f.metadata()?.permissions();
        p.set_mode(0o600);
        std::fs::set_permissions(path, p)?;
        Ok(())
    }

    #[cfg(windows)]
    {
        // In %LOCALAPPDATA%, files inherit a per-user ACL by default.
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        Ok(())
    }
}

// Keystore path helper -> %LOCALAPPDATA%/SchrodingerVault/keystore/mlkem768.sk
fn keystore_path() -> io::Result<PathBuf> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no local data dir"))?;
    let dir = base.join("SchrodingerVault").join("keystore");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("mlkem768.sk"))
}

// Example commands 
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

// Create Vault: PBKDF2-HMAC-SHA-256 + device ML-KEM-768 keypair + self-encap.
#[command]
pub fn create_vault(db: State<AppDb>, master_password: String) -> Result<bool, String> {
    println!("== create_vault ==");
    println!("(debug) received password len = {}", master_password.len());

    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // salts
    let mut salt_pw  = [0u8; 16];
    let mut salt_kdf = [0u8; 32];
    let mut r = rng();
    r.fill_bytes(&mut salt_pw);
    r.fill_bytes(&mut salt_kdf);

    // encode for TEXT storage
    let salt_pw_b64  = B64.encode(salt_pw);
    let salt_kdf_b64 = B64.encode(salt_kdf);

    // KDF params
    let kdf = "pbkdf2-hmac-sha256";
    let kdf_params = r#"{"iterations":310000,"out":32,"algo":"sha256"}"#;

    // PBKDF2 derive K1 (RAM only)
    let iterations: u32 = 310_000;
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password.as_bytes(), &salt_pw, iterations.into(), &mut k1);
    println!("(debug) PBKDF2 derived K1 (32 bytes in RAM)");

    // Device keypair + self-encap
    let (pk_kem_raw, ct_kem_raw) = generate_device_keypair().map_err(|e| e.to_string())?;
    println!(
        "(debug) pk_kem_bytes_len={}, ct_kem_bytes_len={}",
        pk_kem_raw.len(), ct_kem_raw.len()
    );

    // Base64 for TEXT meta
    let pk_kem_b64 = B64.encode(&pk_kem_raw);
    let ct_kem_b64 = B64.encode(&ct_kem_raw);
    let kem_alg = "ML-KEM-768";

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

    println!("(debug) salts + kdf + kem public material stored; SK on disk.");
    println!("== create_vault done ==");
    Ok(true)
}

// Device keypair generator — SK written securely to file, not DB.
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
    println!("(debug) encapsulated: ct={}B, ss={}B",
        ct_kem.as_ref().len(), ss_raw.as_ref().len());

    // Self-check
    let ss2 = kem.decapsulate(&sk_kem, &ct_kem)
        .map_err(|e| format!("decapsulate: {e}"))?;
    debug_assert_eq!(ss_raw.as_ref(), ss2.as_ref());
    println!("(debug) self-check ok: decapsulated ss matches");

    // Write SK securely
    let sk_path = keystore_path().map_err(|e| format!("keystore_path: {e}"))?;
    write_secret_key_secure(&sk_path, sk_kem.as_ref())
        .map_err(|e| format!("write sk: {e}"))?;
    println!("(debug) wrote secret key to: {}", sk_path.to_string_lossy());

    Ok((pk_kem.as_ref().to_vec(), ct_kem.as_ref().to_vec()))
}

// Debug: sizes/status (safe, no FFI).
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

    let (pk_kem_b64_len, pk_kem_bytes_len): (usize, usize) = match pk_b64 {
        Some(ref s) => (s.len(), B64.decode(s).map(|v| v.len()).unwrap_or(0)),
        None => (0, 0),
    };
    let (ct_kem_b64_len, ct_kem_bytes_len): (usize, usize) = match ct_b64 {
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
