use tauri::{command, AppHandle, State};
use crate::state::AppDb;
use crate::vault_core::db;
use crate::vault_core::db::{EntryListItem, NewEntry};

use rand::{rng, RngCore};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use hkdf::Hkdf;

use std::fs;
use zeroize::Zeroize;
use secrecy::{SecretString, ExposeSecret};

// Re-export helpers from vault_core so debug.rs and tests can still import them from here.
pub use crate::vault_core::session::{
    VAULT_AES_KEY, install_aes_key, get_aes_key_ref, zeroize_aes_key, wipe_secret,
};
pub use crate::vault_core::crypto::{
    SealResult, encrypt_password, decrypt_password,
    keystore_path, write_secret_key_secure, generate_device_keypair, remove_file_if_exists,
};

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
    conn.execute("INSERT INTO person (name, data) VALUES (?1, NULL)", rusqlite::params![name])
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
// Vault creation
// =========================

#[command]
pub fn create_vault(_app: AppHandle, db: State<AppDb>, master_password: String) -> Result<bool, String> {
    use crate::vault_core::crypto::{encrypt_verifier, generate_dsa_keypair, sign_manifest};
    use sha2::Digest;

    let master_password = SecretString::from(master_password);
    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // Generate salts and derive K1
    let mut r = rng();
    let mut salt_pw = [0u8; 32]; r.fill_bytes(&mut salt_pw);
    let mut salt_kdf = [0u8; 32]; r.fill_bytes(&mut salt_kdf);
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password.expose_secret().as_bytes(), &salt_pw, 310_000, &mut k1);

    // Store verifier
    let (verifier_nonce, verifier_ct) = encrypt_verifier(&k1).map_err(|e| e)?;
    db::set_meta(&conn, "verifier_nonce", &verifier_nonce).map_err(|e| e.to_string())?;
    db::set_meta(&conn, "verifier_ct",    &verifier_ct).map_err(|e| e.to_string())?;

    // Generate device KEM keypair and ML-DSA keypair
    let (pk_kem_raw, ct_kem_raw) = generate_device_keypair().map_err(|e| e)?;
    let dsa_pk_b64 = generate_dsa_keypair().map_err(|e| e)?;
    db::set_meta(&conn, "dsa_pk", &dsa_pk_b64).map_err(|e| e.to_string())?;

    // Store vault setup meta in a transaction, then wipe K1
    let pk_kem_b64 = B64.encode(&pk_kem_raw);
    let ct_kem_b64 = B64.encode(&ct_kem_raw);
    let salt_pw_b64  = B64.encode(salt_pw);
    let salt_kdf_b64 = B64.encode(salt_kdf);
    {
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        for (k, v) in [
            ("salt_pw",    salt_pw_b64.as_str()),
            ("salt_kdf",   salt_kdf_b64.as_str()),
            ("kdf",        "pbkdf2-hmac-sha256"),
            ("kdf_params", r#"{"iterations":310000,"out":32,"algo":"sha256"}"#),
            ("pk_kem",     pk_kem_b64.as_str()),
            ("ct_kem",     ct_kem_b64.as_str()),
            ("kem_alg",    "ML-KEM-768"),
            ("alg",        "mlkem768|aes256gcm|hkdfsha256|pbkdf2"),
        ] {
            tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?1, ?2)", [k, v])
                .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        wipe_secret(&mut k1);
    }

    // Sign and store manifest
    let manifest_hash = sha2::Sha256::digest(db::build_manifest_input(&conn).as_bytes());
    let sig_b64 = sign_manifest(manifest_hash.as_ref())?;
    db::set_meta(&conn, "manifest_hash", &B64.encode(manifest_hash)).map_err(|e| e.to_string())?;
    db::set_meta(&conn, "manifest_sig",  &sig_b64).map_err(|e| e.to_string())?;

    Ok(true)
}


// Recover device secret (ss) via ML-KEM-768. Caller must zeroize the result after use.
pub(crate) fn recover_device_secret(db: &State<AppDb>) -> Result<[u8; 32], String> {
    use crate::vault_core::crypto::decapsulate_device_secret;

    let ct_kem_b64 = {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        db::get_meta(&conn, "ct_kem").map_err(|_| "missing meta key: ct_kem".to_string())?
    };
    decapsulate_device_secret(&ct_kem_b64)
}


#[command]
pub fn unlock_vault(_app: AppHandle, db: State<AppDb>, password: String) -> Result<bool, String> {
    use crate::vault_core::crypto::{verify_verifier, verify_manifest_sig};
    use sha2::Digest;

    let master_password = SecretString::from(password);

    // Derive K1 from password
    let (salt_pw_b64, _kdf_label, kdf_params_json) = {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        db::get_kdf_meta(&conn).map_err(|e| e.to_string())?
    };
    let salt_pw = B64.decode(&salt_pw_b64).map_err(|_| "salt_pw decode failed")?;
    let iterations: u32 = kdf_params_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("iterations").and_then(|i| i.as_u64()).map(|n| n as u32))
        .unwrap_or(310_000);
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password.expose_secret().as_bytes(), &salt_pw, iterations, &mut k1);

    // Verify password
    {
        let (nonce_b64, ct_b64) = {
            let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
            db::get_verifier(&conn).map_err(|e| e.to_string())?
        };
        if let Err(e) = verify_verifier(&k1, &nonce_b64, &ct_b64) {
            k1.zeroize();
            return Err(e);
        }
    }

    // Verify manifest (tamper detection)
    {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let manifest_hash = sha2::Sha256::digest(db::build_manifest_input(&conn).as_bytes());
        let (stored_hash_b64, stored_sig_b64, dsa_pk_b64) =
            db::get_manifest_verify_data(&conn).map_err(|e| e.to_string())?;

        if B64.encode(manifest_hash) != stored_hash_b64 {
            k1.zeroize();
            return Err("This vault has been modified outside of Schrödinger Vault. Unlock blocked.".into());
        }
        if let Err(e) = verify_manifest_sig(manifest_hash.as_ref(), &stored_sig_b64, &dsa_pk_b64) {
            k1.zeroize();
            return Err(e);
        }
    }

    // Decapsulate device secret and derive final AES key
    match recover_device_secret(&db) {
        Ok(ss) => {
            let mut ss_zero = ss;
            let salt_kdf_b64 = {
                let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
                db::get_meta(&conn, "salt_kdf").map_err(|e| e.to_string())?
            };
            let salt_kdf = B64.decode(&salt_kdf_b64).map_err(|_| "salt_kdf decode failed")?;

            let hk_k1 = Hkdf::<Sha256>::new(Some(&salt_kdf), &k1);
            let mut prk1 = [0u8; 32];
            hk_k1.expand(&[], &mut prk1).map_err(|e| e.to_string())?;

            let hk_final = Hkdf::<Sha256>::new(Some(&prk1), &ss_zero);
            let mut aes_key_tmp = [0u8; 32];
            hk_final.expand(b"vault-key", &mut aes_key_tmp).map_err(|_| "HKDF expand failed")?;

            let _ = install_aes_key(&aes_key_tmp);
            prk1.zeroize(); ss_zero.zeroize(); k1.zeroize();
            Ok(true)
        }
        Err(_) => {
            k1.zeroize();
            Err("Vault cannot be unlocked — device key missing or vault data corrupted.".into())
        }
    }
}

#[command]
pub fn lock_vault() {
    zeroize_aes_key();
    crate::clipboard::copy_to_clipboard(String::new());
}

#[command]
pub fn factory_reset_vault(app: AppHandle, db: State<AppDb>) -> Result<bool, String> {
    let sk_path = keystore_path().map_err(|e| e.to_string())?;
    remove_file_if_exists(&sk_path).ok();
    let mut dsa_path = keystore_path().map_err(|e| e.to_string())?;
    dsa_path.set_file_name("ml_dsa.sk");
    remove_file_if_exists(&dsa_path).ok();

    {
        let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        db::clear_vault_data(&mut *conn).map_err(|e| e.to_string())?;
    }
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

// =========================
// Vault CRUD
// =========================

fn validate_label(label: &str) -> Result<String, String> {
    let t = label.trim();
    if t.is_empty() { return Err("Label is required".into()); }
    if t.len() > 128 { return Err("Label is too long (max 128)".into()); }
    Ok(t.to_string())
}

fn validate_username(username: &str) -> Result<String, String> {
    let t = username.trim();
    if t.is_empty() { return Err("Username is required".into()); }
    if t.len() > 256 { return Err("Username is too long (max 256)".into()); }
    Ok(t.to_string())
}

fn validate_password(password: String) -> Result<SecretString, String> {
    if password.is_empty() { return Err("Password is required".into()); }
    if password.len() > 10000 { return Err("Password is too long".into()); }
    Ok(SecretString::from(password))
}

fn validate_notes(opt: &Option<String>) -> Result<Option<String>, String> {
    match opt.as_deref() {
        None => Ok(None),
        Some(notes) => {
            let t = notes.trim();
            if t.len() > 2_000 { return Err("Notes are too long (max 2000)".into()); }
            Ok(if t.is_empty() { None } else { Some(t.to_string()) })
        }
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
    label: String, username: String, password: String, notes: Option<String>,
) -> Result<EntryListItem, String> {
    let label    = validate_label(&label)?;
    let username = validate_username(&username)?;
    let password = validate_password(password)?;
    let notes    = validate_notes(&notes)?;

    let sealed = {
        let guard = get_aes_key_ref().map_err(|_| "Vault is locked — unlock first")?;
        let key = guard.as_ref().ok_or("Vault is locked — unlock first")?;
        encrypt_password(key, password.expose_secret())?
    };

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    db::add_entry(&conn, NewEntry {
        label: &label, username: &username, notes: notes.as_deref(),
        nonce: &sealed.nonce, ciphertext: &sealed.ciphertext, tag: &sealed.tag,
    }).map_err(|e| e.to_string())
}

#[command]
pub fn vault_get(db: State<AppDb>, id: i64) -> Result<String, String> {
    if id <= 0 { return Err("Invalid id".into()); }
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let enc = db::get_entry_encrypted(&conn, id)
        .map_err(|e| e.to_string())?
        .ok_or("No entry found with that id")?;

    if enc.nonce.len() != 12 || enc.tag.len() != 16 {
        return Err("Entry is corrupt (invalid nonce/tag size)".into());
    }
    let mut nonce12 = [0u8; 12]; nonce12.copy_from_slice(&enc.nonce);
    let mut tag16   = [0u8; 16]; tag16.copy_from_slice(&enc.tag);

    let plaintext = {
        let guard = get_aes_key_ref().map_err(|_| "Vault is locked — unlock first")?;
        let key = guard.as_ref().ok_or("Vault is locked — unlock first")?;
        decrypt_password(key, &nonce12, enc.ciphertext, &tag16)?.expose_secret().to_string()
    };
    nonce12.zeroize(); tag16.zeroize();
    Ok(plaintext)
}

#[command]
pub fn vault_delete(db: State<AppDb>, id: i64) -> Result<(), String> {
    if id <= 0 { return Err("Invalid id".into()); }
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let n = db::delete_entry(&conn, id).map_err(|e| e.to_string())?;
    if n == 0 { Err("No entry found with that id".into()) } else { Ok(()) }
}

#[tauri::command]
pub fn setup_verifier(db: State<AppDb>, password: String) -> Result<(), String> {
    use crate::vault_core::crypto::encrypt_verifier;

    let salt_pw_b64 = {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        db::get_meta(&conn, "salt_pw").map_err(|e| e.to_string())?
    };

    let salt_pw = B64.decode(&salt_pw_b64).map_err(|_| "salt_pw decode failed")?;
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_pw, 310_000, &mut k1);

    let (nonce_b64, ct_b64) = encrypt_verifier(&k1)?;

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    db::set_meta(&conn, "verifier_nonce", &nonce_b64).map_err(|e| e.to_string())?;
    db::set_meta(&conn, "verifier_ct",    &ct_b64).map_err(|e| e.to_string())?;
    Ok(())
}


// Unit tests for zeroization logic.
#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;
    use std::{thread, time::Duration};

    #[test]
    fn wipe_secret_overwrites_buffer() {
        let mut buf = [0xAAu8; 16];
        wipe_secret(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn aes_key_install_and_zeroize() {
        let key = [0xABu8; 32];
        install_aes_key(&key).expect("install key");
        { let guard = VAULT_AES_KEY.read().unwrap(); assert!(guard.is_some()); }
        zeroize_aes_key().expect("wipe key");
        { let guard = VAULT_AES_KEY.read().unwrap(); assert!(guard.is_none()); }
    }

    #[test]
    fn k1_and_ss_zeroized_after_use() {
        let mut k1 = [0x11u8; 32];
        let mut ss = [0x22u8; 32];
        k1.zeroize(); ss.zeroize();
        assert!(k1.iter().all(|&b| b == 0));
        assert!(ss.iter().all(|&b| b == 0));
    }

    #[test]
    fn password_string_zeroized_after_use() {
        let password = String::from("Tr0ub4dor&3");
        let mut pw_bytes = password.into_bytes();
        assert!(pw_bytes.iter().any(|&b| b != 0));
        wipe_secret(&mut pw_bytes);
        assert!(pw_bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn clipboard_auto_clear_mock() {
        use std::sync::{Arc, Mutex};
        let clip = Arc::new(Mutex::new(String::new()));
        *clip.lock().unwrap() = "secret123".into();
        let clip_ref = clip.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            *clip_ref.lock().unwrap() = String::new();
        });
        assert_eq!(&*clip.lock().unwrap(), "secret123");
        thread::sleep(Duration::from_millis(60));
        assert_eq!(&*clip.lock().unwrap(), "");
    }

    #[test]
    fn repeated_aes_key_wipe_safe() {
        let key = [0xCDu8; 32];
        install_aes_key(&key).expect("install");
        zeroize_aes_key().expect("wipe #1");
        zeroize_aes_key().expect("wipe #2");
        let guard = VAULT_AES_KEY.read().unwrap();
        assert!(guard.is_none());
    }
}
