# Packaging Schrodinger Vault

Schrodinger Vault is a Tauri desktop app. The clickable user-facing builds are produced by Tauri from this project:

- macOS: `.app` and `.dmg`
- Windows: `.exe` installer via NSIS and `.msi`
- Linux: `.deb`, `.rpm`, and `.AppImage`

## Build Machine Requirements

Install these before packaging:

- Node.js LTS and npm
- Rust stable, including `cargo`
- Platform build tools:
  - macOS: Xcode Command Line Tools
  - Windows: Microsoft C++ Build Tools / Visual Studio Build Tools
  - Linux: system build tools for compiling Rust and Tauri apps
- Native libraries/tools used by dependencies:
  - `cmake`, required by `oqs-sys` / `liboqs`
  - `pkg-config`, used by native Rust crates
  - OpenSSL 3 development files

On macOS with Homebrew:

```sh
brew install node rust cmake pkg-config openssl@3
```

This repo currently has `src-tauri/.cargo/config.toml` pointing OpenSSL to Homebrew's Apple Silicon path:

```toml
OPENSSL_DIR = "/opt/homebrew/opt/openssl@3"
```

If building on Intel macOS, Linux, Windows, or CI, update/remove that machine-specific path or provide equivalent environment variables.

## Install Project Dependencies

From the app directory:

```sh
cd schrodinger-vault
npm install
```

## Create Clickable Installers

Build all configured bundles for the current operating system:

```sh
npm run build
```

Build a specific platform bundle on that platform:

```sh
npm run build:mac
npm run build:windows
npm run build:linux
```

Tauri writes the finished clickable app/installers under:

```text
src-tauri/target/release/bundle/
```

## Platform Notes

Tauri packaging is most reliable when each platform is built on its own OS:

- Build macOS `.app` / `.dmg` on macOS.
- Build Windows `.exe` / `.msi` on Windows.
- Build Linux `.deb` / `.rpm` / `.AppImage` on Linux.

Cross-compiling is possible for some targets, but native libraries such as `liboqs` and OpenSSL make it more fragile. For a capstone/demo release, use separate build machines or GitHub Actions runners for each operating system.

## Current Local Status

On this machine, packaging cannot run yet because:

- `cargo` is not available on `PATH`.
- npm dependencies are not installed; `npm ls --depth=0` reports missing `@tauri-apps/cli` and `@tauri-apps/plugin-dialog`.

After installing the build requirements and running `npm install`, use `npm run build:mac` on this Mac to produce the macOS clickable app.
