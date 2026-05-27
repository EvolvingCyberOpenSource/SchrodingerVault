# Threat Model

## Goals

Schrodinger Vault is designed to protect locally stored vault entries when the vault is locked and the application data files are copied, inspected, or modified outside the app.

The app is not designed to protect secrets from a fully compromised operating system, malware running as the user, screen capture, keyloggers, memory inspection by privileged processes, or physical attackers with unlocked access to the active session.

## Assets

- Master password
- Derived key material
- Vault entry plaintext
- Encrypted vault database rows
- Local device key files
- Manifest/signature metadata

## Trust Boundaries

- The local device and user account are trusted while the vault is in use.
- The operating system clipboard is treated as shared system state.
- The local filesystem is not trusted to preserve integrity without verification.
- The frontend is trusted app code, but production builds should not expose debug or tamper commands.

## Main Threats

- Offline database theft
- Tampering with encrypted entry rows
- Tampering with vault metadata
- Accidental disclosure through clipboard history
- Launching stale or modified app builds
- Weak master password selection

## Current Mitigations

- Local encrypted storage for vault entries
- Master-password-derived unlock flow
- Runtime-only vault key storage that is cleared on lock and exit paths
- Manifest verification before unlock
- Password-gated factory reset and password change flows
- Signed and notarized macOS release artifacts
- Debug and tamper commands excluded from the production command bridge

## Non-Goals

- Cloud sync
- Enterprise key recovery
- Hardware-backed key storage
- Protection against malware already running in the user's session
- Formal FIPS validation
- Formal audit claims
