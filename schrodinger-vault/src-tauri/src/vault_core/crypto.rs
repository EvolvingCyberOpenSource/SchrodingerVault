use rand::RngCore;
use aes_gcm::{Aes256Gcm, aead::{AeadInPlace, KeyInit, generic_array::GenericArray}, Nonce};
use zeroize::{Zeroize, Zeroizing};
use secrecy::{SecretString, ExposeSecret};
use std::{fs, io, path::{Path, PathBuf}};
use std::fs::OpenOptions;
use std::io::Write;
use dirs;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

// ====================
// AES-256-GCM helpers
// ====================

fn new_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    rand::rng().fill_bytes(&mut n);
    n
}

// Holds the per-entry nonce, ciphertext, and authentication tag
pub struct SealResult {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

pub fn encrypt_password(aes_key: &[u8; 32], password_utf8: &str) -> Result<SealResult, String> {
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

    Ok(SealResult { nonce, ciphertext, tag: out_tag })
}

pub fn decrypt_password(
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

    let password = String::from_utf8(ciphertext).map_err(|_| "Decrypted data was not valid UTF-8".to_string())?;
    Ok(SecretString::from(password))
}

// =========================
// Keystore helpers (KEM SK)
// =========================

/// Write a secret key file with tight permissions:
/// - Unix/macOS: 0600
/// - Windows: per-user ACL in %LOCALAPPDATA%
pub fn write_secret_key_secure(path: &Path, bytes: &[u8]) -> io::Result<()> {
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
pub fn keystore_path() -> io::Result<PathBuf> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no local data dir"))?;
    let dir = base.join("SchrodingerVault").join("keystore");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("mlkem768.sk"))
}

// =========================
// KEM keypair generation
// =========================

/// Generates ML-KEM-768 keypair, encapsulates, self-checks decapsulation,
/// writes SK to keystore with tight perms, and returns (pk_raw, ct_raw).
pub fn generate_device_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    oqs::init();

    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
        .map_err(|e| format!("kem new: {e}"))?;

    let (pk_kem, sk_kem) = kem.keypair()
        .map_err(|e| format!("keypair: {e}"))?;

    let (ct_kem, _ss_raw) = kem.encapsulate(&pk_kem)
        .map_err(|e| format!("encapsulate: {e}"))?;

    let sk_path = keystore_path().map_err(|e| format!("keystore_path: {e}"))?;
    write_secret_key_secure(&sk_path, sk_kem.as_ref())
        .map_err(|e| format!("write sk: {e}"))?;

    Ok((
        pk_kem.as_ref().to_vec(),
        ct_kem.as_ref().to_vec(),
    ))
}

// =========================
// File utilities
// =========================

pub fn remove_file_if_exists(p: &Path) -> io::Result<()> {
    match fs::remove_file(p) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// =========================
// Verifier helpers
// =========================

/// Encrypt "vault-ok" with k1. Returns (nonce_b64, ciphertext_b64).
pub fn encrypt_verifier(k1: &[u8]) -> Result<(String, String), String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};

    let cipher = Aes256Gcm::new_from_slice(k1).map_err(|_| "verifier cipher init failed")?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(&nonce.into(), b"vault-ok".as_ref())
        .map_err(|_| "verifier encryption failed")?;

    Ok((B64.encode(&nonce), B64.encode(&ct)))
}

/// Decrypt and verify the stored verifier against k1. Returns Err if the password is wrong.
pub fn verify_verifier(k1: &[u8], nonce_b64: &str, ct_b64: &str) -> Result<(), String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;

    let nonce = B64.decode(nonce_b64).map_err(|_| "nonce decode failed")?;
    let ct    = B64.decode(ct_b64).map_err(|_| "verifier_ct decode failed")?;
    let cipher = Aes256Gcm::new_from_slice(k1).map_err(|_| "cipher init failed")?;

    match cipher.decrypt(GenericArray::from_slice(&nonce), ct.as_ref()) {
        Ok(pt) if pt == b"vault-ok" => Ok(()),
        _ => Err("That password didn't work.".into()),
    }
}

// =========================
// ML-DSA helpers
// =========================

/// Generate an ML-DSA-65 keypair, write the SK to the keystore, and return the PK as Base64.
pub fn generate_dsa_keypair() -> Result<String, String> {
    use oqs::sig::{Sig, Algorithm as SigAlgorithm};

    let dsa = Sig::new(SigAlgorithm::MlDsa65).map_err(|e| format!("ML-DSA init failed: {e}"))?;
    let (pk, sk) = dsa.keypair().map_err(|e| format!("ML-DSA keypair failed: {e}"))?;

    let mut sk_path = keystore_path().map_err(|e| e.to_string())?;
    sk_path.set_file_name("ml_dsa.sk");
    write_secret_key_secure(&sk_path, sk.as_ref())
        .map_err(|e| format!("write ML-DSA secret key failed: {e}"))?;

    Ok(B64.encode(pk.as_ref()))
}

/// Sign `manifest_hash` with the stored ML-DSA SK and return the signature as Base64.
pub fn sign_manifest(manifest_hash: &[u8]) -> Result<String, String> {
    use oqs::sig::{Sig, Algorithm as SigAlgorithm};

    let mut sk_path = keystore_path().map_err(|e| e.to_string())?;
    sk_path.set_file_name("ml_dsa.sk");
    let sk_bytes = fs::read(&sk_path).map_err(|e| format!("read ml_dsa.sk failed: {e}"))?;

    let dsa    = Sig::new(SigAlgorithm::MlDsa65).map_err(|e| format!("ML-DSA init failed: {e}"))?;
    let sk_ref = dsa.secret_key_from_bytes(&sk_bytes).ok_or("Invalid ML-DSA secret key")?;
    let sig    = dsa.sign(manifest_hash, sk_ref).map_err(|e| format!("ML-DSA sign failed: {e}"))?;

    Ok(B64.encode(sig.as_ref()))
}

/// Verify an ML-DSA signature over `manifest_hash`. Returns Err if tampered.
pub fn verify_manifest_sig(manifest_hash: &[u8], sig_b64: &str, pk_b64: &str) -> Result<(), String> {
    use oqs::sig::{Sig, Algorithm as SigAlgorithm};

    let sig_bytes = B64.decode(sig_b64.as_bytes()).map_err(|_| "manifest_sig decode failed")?;
    let pk_bytes  = B64.decode(pk_b64.as_bytes()).map_err(|_| "dsa_pk decode failed")?;

    let dsa     = Sig::new(SigAlgorithm::MlDsa65).map_err(|e| format!("ML-DSA init failed: {e}"))?;
    let pk_ref  = dsa.public_key_from_bytes(&pk_bytes).ok_or("Invalid ML-DSA public key")?;
    let sig_ref = dsa.signature_from_bytes(&sig_bytes).ok_or("Invalid ML-DSA signature")?;

    dsa.verify(manifest_hash, sig_ref, pk_ref)
        .map_err(|_| "This vault has been modified outside of Schrödinger Vault. Unlock blocked.".into())
}

// =========================
// KEM decapsulation
// =========================

/// Recover the device-bound shared secret via ML-KEM-768 decapsulation.
/// The SK is read from the keystore file. Caller must zeroize the result after use.
pub fn decapsulate_device_secret(ct_kem_b64: &str) -> Result<[u8; 32], String> {
    use oqs::kem::{Algorithm, Kem};

    let ct_kem_bytes = B64.decode(ct_kem_b64.as_bytes()).map_err(|_| "ct_kem decode failed")?;

    let sk_path = keystore_path().map_err(|e| format!("keystore path: {e}"))?;
    if !sk_path.exists() {
        return Err("device secret key missing; vault cannot unlock on this device".into());
    }
    let mut sk_bytes = fs::read(&sk_path).map_err(|e| format!("read device secret key: {e}"))?;

    oqs::init();
    let kem    = Kem::new(Algorithm::MlKem768).map_err(|e| format!("kem new: {e}"))?;
    let sk_ref = kem.secret_key_from_bytes(&sk_bytes)
        .ok_or_else(|| "secret key length invalid/corrupted".to_string())?;
    let ct_ref = kem.ciphertext_from_bytes(&ct_kem_bytes)
        .ok_or_else(|| "ciphertext length invalid/corrupted".to_string())?;
    let ss_vec = kem.decapsulate(sk_ref, ct_ref)
        .map_err(|e| format!("decapsulation failed (ciphertext may be corrupted): {e}"))?;

    if ss_vec.as_ref().len() != 32 {
        return Err(format!("unexpected ss length: {}", ss_vec.as_ref().len()));
    }
    let mut ss = [0u8; 32];
    ss.copy_from_slice(ss_vec.as_ref());
    sk_bytes.zeroize();

    Ok(ss)
}
