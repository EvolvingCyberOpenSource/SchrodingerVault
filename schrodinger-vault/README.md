# Schrodinger Vault

Schrodinger Vault is an open-source, local-first encrypted vault application built with Tauri.

This project is currently an early release. It is intended for local password and secret storage experiments, education, and continued security review. It has not completed an independent security audit and should not be described as FIPS validated.

## Platform Support

- macOS Universal: Apple Silicon and Intel
- Windows and Linux builds are planned

## Security Model

- Vault data is stored locally on the user's device.
- The app does not require cloud connectivity.
- The master password is used to derive key material for unlocking the vault.
- Entries are encrypted before being stored in the local database.
- The macOS release is signed and notarized with Developer ID distribution.
- Post-quantum cryptography concepts are used with ML-KEM and ML-DSA primitives.

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before relying on this project for sensitive production use.

## Development

Install dependencies:

```sh
npm install
```

Run the app locally:

```sh
npm run dev
```

Build macOS packages:

```sh
npm run build:mac
```

Build macOS universal packages:

```sh
npm run build:mac:universal
```
