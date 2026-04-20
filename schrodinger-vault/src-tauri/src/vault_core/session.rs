use std::sync::RwLock;
use zeroize::{Zeroize, Zeroizing};

// Store AES-256 session key wrapped in Zeroizing so it is wiped on lock/exit.
pub static VAULT_AES_KEY: RwLock<Option<Zeroizing<[u8; 32]>>> = RwLock::new(None);

// Installs AES key in RAM (old key auto-wiped by Zeroizing on replace)
pub fn install_aes_key(key: &[u8; 32]) -> Result<(), &'static str> {
    let mut guard = VAULT_AES_KEY.write().map_err(|_| "lock poisoned")?;
    *guard = Some(wrap_key(*key));
    Ok(())
}

// Reads currently installed AES key by reference. Caller must hold the guard.
//
// Example:
//   let guard = get_aes_key_ref()?;
//   let aes_key = guard.as_ref();
pub fn get_aes_key_ref<'a>(
) -> Result<std::sync::RwLockReadGuard<'a, Option<Zeroizing<[u8; 32]>>>, &'static str> {
    VAULT_AES_KEY.read().map_err(|_| "lock poisoned")
}

// Wipe currently installed AES key (dropping Zeroizing wipes memory)
pub fn zeroize_aes_key() -> Result<(), &'static str> {
    let mut guard = VAULT_AES_KEY.write().map_err(|_| "lock poisoned")?;
    if let Some(ref mut key) = *guard {
        key.zeroize();
    }
    *guard = None;
    Ok(())
}

// Overwrite a mutable buffer with zeros.
pub fn wipe_secret(buf: &mut [u8]) {
    buf.zeroize();
}

fn wrap_key(key: [u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(key)
}
