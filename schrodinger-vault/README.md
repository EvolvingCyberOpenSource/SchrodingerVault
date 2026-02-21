# Schrödinger's Vault

A post-quantum cryptography-enabled desktop password manager built with [Tauri](https://tauri.app/) (Rust + JavaScript).

## Features

- **Post-quantum security** — Uses ML-KEM-768 for device-bound key encapsulation and ML-DSA-65 for tamper detection signatures
- **Strong symmetric encryption** — AES-256-GCM with per-entry random nonces
- **Password-based key derivation** — PBKDF2-HMAC-SHA256 with 310,000 iterations
- **Memory safety** — All secrets are zeroized from memory on lock, exit, or crash via the `zeroize` crate
- **Tamper detection** — Vault manifest is signed on creation and verified on every unlock
- **Auto-lock** — Vault locks after 5 minutes of inactivity, on window close, or on Ctrl+C
- **Brute-force protection** — Exponential backoff after failed unlock attempts; hard lockout after 5 failures
- **Clipboard protection** — Clipboard is cleared after 30 seconds; Windows uses a special API to prevent clipboard history retention
- **Cross-platform** — macOS, Windows, and Linux

## Cryptography

Schrödinger's Vault uses a layered cryptographic scheme:

```
Master Password + Salt_PW
        ↓ PBKDF2-HMAC-SHA256 (310,000 iterations)
       K1

ML-KEM-768 keypair generated on vault creation
  sk_kem → stored on disk (0600 permissions on Unix)
  pk_kem + ct_kem → stored in database
  On unlock: Decaps(sk_kem, ct_kem) → shared secret ss

K1 + ss + Salt_KDF
        ↓ HKDF-SHA256
      K_aes (held in RAM only, wiped on lock)

Per entry:
  Password + K_aes + random 12-byte nonce
        ↓ AES-256-GCM
  (nonce, ciphertext, tag) → stored in database

Manifest integrity:
  Vault metadata hashed and signed with ML-DSA-65
  Signature verified on every unlock
```

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Framework | Tauri 2 |
| Backend | Rust |
| Frontend | Vanilla HTML/CSS/JavaScript |
| Database | SQLite (via rusqlite) |
| Post-quantum KEM | ML-KEM-768 (via liboqs) |
| Post-quantum signatures | ML-DSA-65 (via liboqs) |
| Symmetric encryption | AES-256-GCM (aes-gcm) |
| Key derivation | PBKDF2 + HKDF |
| Secret handling | zeroize, secrecy |

## Data Storage

Vault data is stored in the platform-specific application data directory:

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/schrodinger-vault/` |
| Windows | `%LOCALAPPDATA%\schrodinger-vault\` |
| Linux | `~/.local/share/schrodinger-vault/` |

Two files are stored:
- **`vault.sqlite`** — Encrypted entries, salts, public keys, and manifest
- **`keystore/mlkem768.sk`** and **`keystore/ml_dsa.sk`** — Device secret keys (permissions: 0600 on Unix)

## Prerequisites

- [Node.js](https://nodejs.org/) (for the Tauri CLI)
- [Rust](https://www.rust-lang.org/tools/install) (stable toolchain)
- [liboqs](https://github.com/open-quantum-safe/liboqs) build dependencies (cmake, a C compiler)
- Platform build tools:
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Microsoft C++ Build Tools, WebView2
  - **Linux**: `libwebkit2gtk`, `libgtk-3`, and related packages (see [Tauri prerequisites](https://tauri.app/start/prerequisites/))

## Getting Started

```bash
# Install JavaScript dependencies
npm install

# Run in development mode
npm run tauri dev

# Build a release binary
npm run tauri build
```

## Usage

1. **Create a vault** — On first launch, set a master password (minimum 10 characters).
2. **Add entries** — Store a label, username, password, and optional notes for each credential.
3. **Unlock** — Enter your master password to decrypt the session key and access your entries.
4. **View/copy passwords** — Passwords are revealed on demand and auto-hidden after 10 seconds. Copying auto-clears the clipboard after 30 seconds.
5. **Lock** — Lock manually, or the vault locks automatically after 5 minutes of inactivity.
6. **Factory reset** — A full reset option is available from the unlock screen if needed.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)

## License

MIT — Copyright 2025 EvolvingCyberOpenSource
