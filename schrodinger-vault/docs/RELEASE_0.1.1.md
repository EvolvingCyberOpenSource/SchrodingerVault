# Password Manager 0.1.1 maintenance release

This is the desktop Password Manager, not the separate Secret Manager.

## Fixes

- Prevent overlapping create/unlock form submissions, clear submitted password fields, and keep the frontend five-failure lockout from being re-enabled by its retry timer. Clearing JavaScript references does not guarantee physical memory erasure.

- Require an unlocked backend session for listing metadata and deleting entries.
- Enforce the creation password minimum in the backend, and refuse to overwrite a partially initialized vault instead of treating it as empty.
- Hold the session-key read guard through add/update database writes, with consistent database-first lock ordering, so locking or key replacement cannot interleave between encryption and persistence.
- Reject malformed verifier nonce lengths without panicking.
- Reject malformed, overflowing, or excessive KDF parameters before doing expensive work. Normal application-generated PBKDF2 and Argon2id settings are unchanged.
- Fix recursive/invalid panic-hook handling and use nonblocking best-effort key cleanup. Cleanup cannot be guaranteed if the key lock is held during a panic.
- Zeroize managed decrypted byte buffers on UTF-8 validation errors as well as success.
- Restrict the macOS/Unix vault directory and keystore directory to owner-only access; restrict the database file to mode 0600.
- Clear the active session after a successful factory reset.
- Enable a local-resource Content Security Policy. Configuration follows https://v2.tauri.app/security/csp/.

## Compatibility and remaining limitations

The application identifier, database schema, key derivation, and keystore location are unchanged. This update does not migrate or overwrite an existing vault. Back up the database and keystore together before updating, and never reset a real vault as an installation test.

This remains an early research release, not an independently audited product. The Password Manager retains its legacy password-only verifier: a copied database allows offline password guesses, although record decryption additionally requires the device key. Labels, usernames, and notes are stored as plaintext metadata, and record ciphertexts are not cryptographically bound to that metadata. The manifest verification key is stored in the database, so manifest signatures are not an external trust anchor against wholesale database replacement. There is no rollback protection or hardware-backed device binding. The inactivity timer is enforced by the desktop frontend. Ongoing OS compromise, clipboard copies, and receiving applications remain outside its protection.

Combined-key verifier migration, metadata authentication, backend-enforced session expiry, and deeper concurrent lifecycle testing need separate review before stronger security claims. The Secret Manager's protections must not be assumed to apply to this Password Manager release.

## Verification

The development-machine run passed 16 Rust unit tests and 3 Node form-behavior tests using synthetic inputs. JavaScript syntax checks and Rust formatting checks also passed. Form tests use a mock DOM and command bridge; they do not establish native webview behavior.

Use synthetic data only. Automated checks must cover locked listing/deletion, malformed verifier nonces, bounded KDF parameters, panic cleanup, and existing cryptographic and zeroization behavior. A universal binary includes both architectures; inclusion does not establish runtime validation on both.
