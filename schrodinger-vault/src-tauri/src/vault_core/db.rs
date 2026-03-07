use rusqlite::{Connection, Result, params, Row, OptionalExtension};
use std::path::PathBuf;
use tauri::{AppHandle, State, command, Manager, path::BaseDirectory};
use crate::state::AppDb;
use crate::commands::{generate_device_keypair, keystore_path, write_secret_key_secure, wipe_secret};
use secrecy::{SecretString, ExposeSecret};

use zeroize::{Zeroize};

use std::{fs};

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use rand::{rng, RngCore};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Resolves the full path to the `vault.sqlite` database file.
///
/// # Arguments
/// * `app` - a handle to the running Tauri application
///
/// # Returns
/// The path to where the database file will be located on the system
pub fn db_path(app: &tauri::AppHandle) -> PathBuf {
    app.path()
        .resolve("vault.sqlite", BaseDirectory::AppData)
        .expect("failed to resolve AppData path")
}

/// Return structs for query functions
// TODO: move into separate file in utils folder
#[derive(serde::Serialize)]
pub struct EntryListItem {
    pub id: i64,
    pub label: String,
    pub username: String,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct NewEntry<'a> {
    pub label: &'a str,
    pub username: &'a str,
    pub notes: Option<&'a str>,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8],
}

#[derive(serde::Serialize)]
pub struct EncEntry {
    pub label: String,
    pub username: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}


/// open the database and create schema if needed returning a connection object
pub fn open_and_init(app: &tauri::AppHandle) -> Result<Connection> {
    let path = db_path(app);

    // TODO: can get rid of this debug in the future
    println!("SQLite DB located at: {}", path.display());

    // saftey check to ensure the directory where the db will be exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // creates the database file (if it doesn't exist)
    let conn = Connection::open(path)?;

    // Good defaults for desktop apps (requires rusqlite >= 0.29)
    let _ = conn.pragma_update(None, "journal_mode", &"WAL");
    let _ = conn.pragma_update(None, "synchronous", &"FULL");

    // Needed by create_vault()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    // test table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS person (
           id    INTEGER PRIMARY KEY AUTOINCREMENT,
           name  TEXT NOT NULL,
           data  BLOB
         )",
        [],
    )?;

    // table for the user (legacy demo; to be deleted later)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user (
            id              INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash   TEXT    NOT NULL,
            salt            BLOB    NOT NULL
        )",
        [],
    )?;

    // TODO: remove later and replace with correct schema in another function and call that here instead
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            label       TEXT NOT NULL UNIQUE,
            username    TEXT NOT NULL,
            notes       TEXT,
            nonce       BLOB NOT NULL,
            ciphertext  BLOB NOT NULL,
            tag         BLOB NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )",
        [],
    )?;

    // Helpful index for listing/search
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_entries_label ON entries(label)",
        [],
    )?;

    Ok(conn)
}


/// Query functions for entries table.
///
/// # Arguments
/// * `conn` - connection to the SQLite database
///
/// # Returns
/// A vector of `EntryListItem` structs representing all entries in the entry table
pub fn list_entries(conn: &Connection) -> Result<Vec<EntryListItem>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, label, username, notes, created_at, updated_at
        FROM entries
        ORDER BY label COLLATE NOCASE
        "#,
    )?;
    let rows = stmt.query_map([], |row| row_to_list_item(row))?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

// Helper, converts db row into EntryListItem
fn row_to_list_item(row: &Row) -> rusqlite::Result<EntryListItem> {
    Ok(EntryListItem {
        id: row.get(0)?,
        label: row.get(1)?,
        username: row.get(2)?,
        notes: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

pub fn add_entry(conn: &Connection, e: NewEntry) -> Result<EntryListItem> {
    conn.execute(
        r#"
        INSERT INTO entries (label, username, notes, nonce, ciphertext, tag)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![e.label, e.username, e.notes, e.nonce, e.ciphertext, e.tag],
    )?;

    // Prepare to return added entry so it can be displayed in UI immediately
    let id = conn.last_insert_rowid();
    let mut stmt = conn.prepare(
        r#"
        SELECT id, label, username, notes, created_at, updated_at
        FROM entries
        WHERE id = ?1
        "#,
    )?;

    let item = stmt.query_row(params![id], |row| row_to_list_item(row))?;
    Ok(item)
}

pub fn delete_entry(conn: &Connection, id: i64) -> Result<usize> {
    conn.execute("DELETE FROM entries WHERE id = ?1", params![id])
}


pub fn get_entry_encrypted(conn: &Connection, id: i64) -> Result<Option<EncEntry>> {
    let mut stmt = conn.prepare(
        "SELECT label, username, nonce, ciphertext, tag FROM entries WHERE id = ?1"
    )?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(EncEntry {
            label: row.get(0)?,
            username: row.get(1)?,
            nonce: row.get(2)?,
            ciphertext: row.get(3)?,
            tag: row.get(4)?,
        }))
    } else {
        Ok(None)
    }
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


    {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        let verifier_plain = b"vault-ok";
        let cipher = Aes256Gcm::new_from_slice(&k1).unwrap();

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let verifier_ct = cipher
            .encrypt(&nonce.into(), verifier_plain.as_ref())
            .expect("verifier encryption failed");

        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('verifier_nonce', ?1)",
            [B64.encode(&nonce)],
        ).map_err(|_| "insert verifier_nonce failed")?;

        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('verifier_ct', ?1)",
            [B64.encode(&verifier_ct)],
        ).map_err(|_| "insert verifier_ct failed")?;

    }
    

    // Device KEM keypair + self-encapsulation (returns pk, ct, ss)
    let (pk_kem_raw, ct_kem_raw) = generate_device_keypair()
        .map_err(|e| e.to_string())?;

    // =======================================
    // ML-DSA KEYPAIR (signatures for manifest)
    // =======================================
    use oqs::sig::{Sig, Algorithm as SigAlgorithm};

    let dsa = Sig::new(SigAlgorithm::MlDsa65)
        .map_err(|e| format!("ML-DSA init failed: {}", e))?;
    
    let (dsa_pk, dsa_sk) = dsa
        .keypair()
        .map_err(|e| format!("ML-DSA keypair failed: {}", e))?;
    
    let dsa_pk_b64 = B64.encode(dsa_pk.as_ref());
    
    // store ML-DSA public key in meta
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('dsa_pk', ?1)",
        [&dsa_pk_b64],
    ).map_err(|e| format!("insert dsa_pk failed: {}", e))?;
    
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
        // Immediately wipe K1 after it's used for verifier + meta storage (intermediate secret)
        wipe_secret(&mut k1);
    }

     // --- Manifest creation for tamper detection ---
{
    use sha2::{Digest, Sha256};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    // Re-acquire a read handle
    let mut manifest_input = String::new();
    for key in ["salt_pw", "salt_kdf", "pk_kem", "ct_kem", "verifier_nonce", "verifier_ct"] {
        let value: String = conn.query_row(
            "SELECT value FROM meta WHERE key=?1", [key],
            |r| r.get::<_, String>(0)
        ).unwrap_or_default();
        manifest_input.push_str(&value);
    }

    // Compute hash
    let manifest_hash = Sha256::digest(manifest_input.as_bytes());
    let manifest_b64 = B64.encode(manifest_hash);

    // -------- REAL ML-DSA SIGNATURE --------

    let mut dsa_sk_path = keystore_path().map_err(|e| e.to_string())?;
    dsa_sk_path.set_file_name("ml_dsa.sk");

    let dsa_sk_bytes = std::fs::read(&dsa_sk_path)
        .map_err(|e| format!("read ml_dsa.sk failed: {e}"))?;

    let dsa = Sig::new(SigAlgorithm::MlDsa65)
        .map_err(|e| format!("ML-DSA init failed: {}", e))?;

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
    ).map_err(|e| format!("insert manifest_hash failed: {e}"))?;
    
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('manifest_sig', ?1)",
        [&signature_b64],
    ).map_err(|e| format!("insert manifest_sig failed: {e}"))?;

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
pub(crate) fn recover_device_secret(db: &State<AppDb>) -> Result<[u8; 32], String> {
    use oqs::kem::{Algorithm, Kem};

    // 1) Fetch ct_kem (b64) from meta
    let ct_kem_b64: String = {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        conn.query_row(
            "SELECT value FROM meta WHERE key='ct_kem'",
            [],
            |r| r.get::<_, String>(0),
        )
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
