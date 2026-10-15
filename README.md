# @authoritydmc/trust-cert

> Zero-dependency CLI to inspect, extract, and auto-install TLS/SSL certificates and root CAs directly into Windows, macOS, and Linux OS trust stores.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/@authoritydmc/trust-cert.svg)](https://www.npmjs.com/package/@authoritydmc/trust-cert)

---

## ⚡ Instant Run via npx

No installation needed. Run directly from your terminal:

```bash
# Inspect and install the root CA / cert for any website or local server:
npx @authoritydmc/trust-cert https://rajlab.lan

# Auto-confirm and install without interactive prompt:
npx @authoritydmc/trust-cert https://rajlab.lan --yes

# Export the extracted certificate to disk:
npx @authoritydmc/trust-cert https://rajlab.lan --out ./lab-ca.crt

# Windows (User store only, no admin privilege prompt):
npx @authoritydmc/trust-cert https://rajlab.lan --user
```

---

## 🚀 Key Features

- **Zero External Dependencies:** Built with 100% native Node.js APIs (`tls`, `crypto`, `child_process`, `fs`). Runs instantaneously through `npx` with zero package download bloat.
- **Automatic Chain Traversal:** Automatically traverses the TLS certificate hierarchy to identify the **Root / Intermediate CA** (Trust Anchor) rather than just trusting an ephemeral leaf certificate.
- **Cross-Platform Auto-Installation:**
  - **Windows:** Automatically invokes `certutil -addstore Root <cert>` (or `-user Root`).
  - **macOS:** Automatically invokes `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`.
  - **Linux (Ubuntu / Debian):** Copies to `/usr/local/share/ca-certificates/` and runs `update-ca-certificates`.
  - **Linux (RHEL / Fedora / CentOS):** Copies to `/etc/pki/ca-trust/source/anchors/` and runs `update-ca-trust`.
  - **Linux (Arch):** Runs `trust anchor`.
- **Smart DNS & Local IP Fallback:** If connecting to `.lan` or `.local` domains before local DNS is populated, automatically attempts LAN IP fallbacks while preserving the TLS SNI header.
- **Safe & Transparent:** Prints the full certificate summary (Subject, Issuer, Validity, SHA-256 fingerprint, SANs) and asks for user confirmation before touching the OS trust store.

---

## 📦 How to Publish to npm

1. **Log in to npm:**
   ```bash
   npm login
   ```
2. **Publish the package (public scoped package):**
   ```bash
   cd packages/trust-cert
   npm publish --access public
   ```
3. Once published, anyone can run:
   ```bash
   npx @authoritydmc/trust-cert https://your-server.lan
   ```

---

## 📄 License

MIT © [Raj Dubey (RajLabs)](https://github.com/authoritydmc)
