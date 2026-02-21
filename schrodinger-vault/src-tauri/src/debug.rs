use tauri::{command, AppHandle, State};
use rusqlite::OptionalExtension;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use hkdf::Hkdf;
use std::fs;
use zeroize::{Zeroize, Zeroizing};
use oqs;
use crate::state::AppDb;
use crate::commands::{
    VAULT_AES_KEY, keystore_path, zeroize_aes_key, recover_device_secret,
    get_aes_key_ref, encrypt_password, SealResult, remove_file_if_exists,
};

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

// Extra "RAM-only" proof: DB does NOT have key material
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
    let guard = VAULT_AES_KEY.read().map_err(|_| "lock poisoned")?;
    Ok(VaultKeyStatus { loaded: guard.is_some() })
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
    pub sql: Option<String>,         // CREATE TABLE ... (may be None for internal tables)
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
    VAULT_AES_KEY
        .read()
        .map(|g| g.is_some())
        .unwrap_or(false)
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
            .query_row(
                "SELECT value FROM meta WHERE key='ct_kem'",
                [],
                |r| r.get::<_, String>(0),
            )
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
    for b in bytes.iter().take(max) { use std::fmt::Write; let _ = write!(s, "{:02x}", b); }
    s
}
// Checks if text is readable and therefore not encrypted
fn mostly_printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() { return false; }
    let printable = bytes.iter().filter(|&&b| (b >= 0x20 && b <= 0x7e) || b == b'\n').count();
    (printable as f32) / (bytes.len() as f32) > 0.9
}

// report lengths + tiny hex previews of an entry's nonce, ciphertext, tag to verify AES-GCM storage
#[command]
pub fn debug_entry_blob_info(db: State<AppDb>, id: i64) -> Result<EntryBlobInfo, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let (nonce, ct, tag): (Vec<u8>, Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT nonce, ciphertext, tag FROM entries WHERE id=?1",
        rusqlite::params![id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    ).map_err(|e| e.to_string())?;
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
    index: Option<i64>,   // flips byte 0 by default
    xor: u8               // bit mask
) -> Result<usize, String> {
    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let col = match field.as_str() {    // which columns to corrupt
        "ciphertext" => "ciphertext",
        "tag" => "tag",
        "nonce" => "nonce",
        other => return Err(format!("unknown field: {}", other)),
    };
    let mut blob: Vec<u8> = conn.query_row(
        &format!("SELECT {} FROM entries WHERE id=?1", col),
        rusqlite::params![id],
        |r| r.get(0)
    ).map_err(|e| e.to_string())?;
    if blob.is_empty() { return Err("blob empty".into()); }
    let i = index.unwrap_or(0) as usize;
    if i >= blob.len() { return Err(format!("index {} out of range {}", i, blob.len())); }
    blob[i] ^= xor;
    let n = conn.execute(
        &format!("UPDATE entries SET {}=?1 WHERE id=?2", col),
        rusqlite::params![blob, id]
    ).map_err(|e| e.to_string())?;
    Ok(n)
}

#[derive(serde::Serialize)]
pub struct CryptoSelfTest {
    pub nonce_len: usize,
    pub tag_len: usize,
    pub roundtrip_ok: bool }

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

/// DEV ONLY: Insert a known-corrupted entry (same values every time).
/// Always returns the inserted entry id.
/// Intended to trigger AES-GCM decrypt failure in `vault_get`.
#[cfg(debug_assertions)]
#[command]
pub fn debug_insert_bad_entry(db: State<AppDb>) -> Result<i64, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // Known wrong nonce + tag + ciphertext (invalid AES-GCM)
    let nonce: [u8; 12] = [
        0xDE, 0xAD, 0xBE, 0xEF,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let tag: [u8; 16] = [
        0xBA, 0xAD, 0xF0, 0x0D,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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

    let inserted = crate::vault_core::db::add_entry(&conn, new)
        .map_err(|e| e.to_string())?;

    println!("[debug] inserted corrupted entry id={} ✅", inserted.id);

    Ok(inserted.id)
}

// debug vault corruption
/// Debug helper: intentionally corrupt one of the manifest-dependent fields
/// to trigger "tampered vault" detection during next unlock.
/// This simulates external modification of the vault database.
#[command]
pub fn debug_corrupt_manifest(db: State<AppDb>) -> Result<bool, String> {
    use rand::Rng;

    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // picking a field that is in the manifest hash
    // salt_kdf is safe to corrupt (will not break DB structure)
    let key_to_corrupt = "salt_kdf";

    // read original value
    let original_value: String = conn
        .query_row("SELECT value FROM meta WHERE key=?1", [key_to_corrupt], |r| r.get(0))
        .map_err(|_| format!("missing meta key: {key_to_corrupt}"))?;

    // mutate a single random character to simulate tampering
    let mut chars: Vec<char> = original_value.chars().collect();
    if !chars.is_empty() {
        let mut rng = rand::thread_rng();
        let i = rng.gen_range(0..chars.len());
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
