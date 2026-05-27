# Security Policy

## Supported Versions

Schrodinger Vault is pre-1.0 software. Security fixes are applied to the main development branch and future tagged releases.

## Reporting a Vulnerability

Please do not open public issues for vulnerabilities that expose secrets, bypass vault access controls, corrupt encrypted data, or weaken key handling.

Report security concerns privately to Evolving Cyber through the project's published contact channel. Include:

- Affected version or commit
- Operating system and CPU architecture
- Reproduction steps
- Expected and actual behavior
- Any logs or crash reports that do not contain real secrets

## Current Security Status

This project has not completed an independent security audit. It should be treated as an early open-source release under active hardening.

Known areas for continued review:

- Cryptographic design review
- Master password KDF parameters and migration path
- Clipboard lifetime and platform behavior
- Secure memory handling limits in desktop applications
- Local database tamper detection and recovery behavior
- Windows and Linux package signing/distribution

## Claims

Do not describe this project as FIPS certified, FIPS validated, audited, or production-hardened unless those reviews and validations are completed and documented.
