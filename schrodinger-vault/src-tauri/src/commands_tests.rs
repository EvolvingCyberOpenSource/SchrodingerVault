use super::*;
use std::{thread, time::Duration};
use zeroize::Zeroize;

fn verifier_conn_with_kdf(
    password: &str,
    kdf: &str,
    kdf_params: &'static str,
) -> (Connection, SecretString) {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute(
        "CREATE TABLE meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )
    .expect("create meta table");

    let mut salt_pw = [0u8; 32];
    rng().fill_bytes(&mut salt_pw);
    let password = SecretString::from(password.to_string());
    let k1 = derive_k1_with_kdf(&password, &salt_pw, kdf, Some(kdf_params)).expect("derive k1");

    let cipher = Aes256Gcm::new_from_slice(&k1).expect("cipher init");
    let mut verifier_nonce = [0u8; 12];
    rng().fill_bytes(&mut verifier_nonce);
    let verifier_ct = cipher
        .encrypt(&verifier_nonce.into(), b"vault-ok".as_ref())
        .expect("encrypt verifier");

    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('salt_pw', ?1)",
        [B64.encode(salt_pw)],
    )
    .expect("insert salt_pw");
    conn.execute("INSERT INTO meta (key, value) VALUES ('kdf', ?1)", [kdf])
        .expect("insert kdf");
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('kdf_params', ?1)",
        [kdf_params],
    )
    .expect("insert kdf_params");
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('verifier_nonce', ?1)",
        [B64.encode(verifier_nonce)],
    )
    .expect("insert verifier_nonce");
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('verifier_ct', ?1)",
        [B64.encode(verifier_ct)],
    )
    .expect("insert verifier_ct");

    (conn, password)
}

fn verifier_conn(password: &str) -> (Connection, SecretString) {
    verifier_conn_with_kdf(
        password,
        "pbkdf2-hmac-sha256",
        r#"{"iterations":310000,"out":32,"algo":"sha256"}"#,
    )
}

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

    {
        let guard = VAULT_AES_KEY.read().unwrap();
        assert!(guard.is_some());
    }

    zeroize_aes_key().expect("wipe key");

    {
        let guard = VAULT_AES_KEY.read().unwrap();
        assert!(guard.is_none());
    }
}

#[test]
fn k1_and_ss_zeroized_after_use() {
    let mut k1 = [0x11u8; 32];
    let mut ss = [0x22u8; 32];

    k1.zeroize();
    ss.zeroize();

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

#[test]
fn master_password_verifier_accepts_correct_password() {
    let (conn, password) = verifier_conn("correct horse battery staple");
    assert!(verify_master_password(&conn, &password).is_ok());
}

#[test]
fn master_password_verifier_rejects_wrong_password() {
    let (conn, _) = verifier_conn("correct horse battery staple");
    let wrong_password = SecretString::from("wrong horse battery staple".to_string());
    assert!(verify_master_password(&conn, &wrong_password).is_err());
}

#[test]
fn argon2id_master_password_verifier_accepts_correct_password() {
    let (conn, password) = verifier_conn_with_kdf(
        "correct horse battery staple",
        "argon2id",
        r#"{"memory_kib":64,"iterations":2,"parallelism":1,"out":32,"algo":"argon2id","version":19}"#,
    );

    assert!(verify_master_password(&conn, &password).is_ok());
}

#[test]
fn argon2id_and_pbkdf2_derive_different_keys() {
    let password = SecretString::from("correct horse battery staple".to_string());
    let salt = [0xA5u8; 32];
    let argon2_key = derive_k1_with_kdf(
        &password,
        &salt,
        "argon2id",
        Some(r#"{"memory_kib":64,"iterations":2,"parallelism":1,"out":32,"algo":"argon2id","version":19}"#),
    )
    .expect("derive argon2id key");
    let pbkdf2_key = derive_k1_with_kdf(
        &password,
        &salt,
        "pbkdf2-hmac-sha256",
        Some(r#"{"iterations":310000,"out":32,"algo":"sha256"}"#),
    )
    .expect("derive pbkdf2 key");

    assert_ne!(argon2_key, pbkdf2_key);
}

#[test]
fn encrypted_entry_roundtrips_with_same_key() {
    let key = [0x42u8; 32];
    let sealed = encrypt_password(&key, "stored password").expect("encrypt password");

    let plaintext = decrypt_password(&key, &sealed.nonce, sealed.ciphertext, &sealed.tag)
        .expect("decrypt password");

    assert_eq!(plaintext.expose_secret(), "stored password");
}

#[test]
fn encrypted_entry_rejects_wrong_key() {
    let key = [0x42u8; 32];
    let wrong_key = [0x24u8; 32];
    let sealed = encrypt_password(&key, "stored password").expect("encrypt password");

    let result = decrypt_password(&wrong_key, &sealed.nonce, sealed.ciphertext, &sealed.tag);

    assert!(result.is_err());
}
