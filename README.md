<div align="center">
  <img src="src/assets/VaultGuardV3.png" width="120" alt="VaultGuard">

  # VaultGuard

  **A fast, secure, local-first password manager.**  
  Built with Tauri and Rust. Your vault never leaves your device.

  ![License](https://img.shields.io/badge/license-MIT-blue)
  ![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
  ![Build](https://img.shields.io/badge/build-passing-brightgreen)
</div>

---

## Features

- 🔒 AES-256-GCM encrypted vault — Argon2id key derivation
- 🚫 Zero cloud, zero accounts, zero telemetry — 100% local
- 🔑 Master password only — if you forget it, the vault cannot be recovered
- 🛡 Progressive lockout after failed attempts (12h → 24h → 1 week)
- 📋 Smart clipboard with auto-clear and copy confirmation
- 🗂 Categories: Login, API Keys, Other — plus custom categories
- 🔍 Real-time search across title, username, and URL
- 🎲 Password generator with accurate entropy-based strength meter
- 📥 Import: Bitwarden JSON, KeePass XML, 1Password CSV, LastPass CSV, Dashlane CSV
- 📤 Export: Encrypted backup, KeePass XML, Bitwarden JSON
- 🌙 Dark and light theme with system preference detection
- 🌍 English and German language support
- ⌨️ Full keyboard shortcut support

---

## Installation

### Linux (all distros)

**Requirements:**
- [Rust](https://rustup.rs) (installs `cargo` automatically)
- `cargo-tauri`: install with `cargo install tauri-cli`
- System dependencies for Tauri (WebKit2GTK):
  - **Arch:** `sudo pacman -S webkit2gtk base-devel`
  - **Debian/Ubuntu:** `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev`
  - **Fedora:** `sudo dnf install webkit2gtk4.1-devel gtk3-devel`

**Install:**
```bash
git clone https://github.com/Viperzz6988/VaultGuard
cd VaultGuard
./install.sh
```

The script detects your distro, builds VaultGuard, and installs it. VaultGuard will appear in your app launcher after installation.

**Manual install if the script fails:**
```bash
cargo tauri build
# Debian/Ubuntu:
sudo dpkg -i src-tauri/target/release/bundle/deb/vaultguard_*.deb
# Fedora/RHEL:
sudo rpm -i src-tauri/target/release/bundle/rpm/vaultguard-*.rpm
# Any distro (manual):
cp src-tauri/target/release/vaultguard ~/.local/bin/
```

---

### Windows

**Requirements:**
- [Rust](https://rustup.rs) — run the installer, select the MSVC toolchain
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) — install "Desktop development with C++"
- `cargo-tauri`: open a terminal and run `cargo install tauri-cli`

**Option 1 — Download installer (easiest):**  
Go to [Releases](https://github.com/Viperzz6988/VaultGuard/releases) and download `vaultguard_setup.msi`.  
Run it — VaultGuard will appear in your Start Menu.

**Option 2 — Build from source:**
```powershell
git clone https://github.com/Viperzz6988/VaultGuard
cd VaultGuard
cargo tauri build
```
The `.msi` installer will be in `src-tauri\target\release\bundle\msi\`.

---

## First Launch

1. Open VaultGuard from your app launcher or Start Menu
2. Create a **master password** — this is the only key to your vault
   - ⚠️ This password is never stored anywhere
   - ⚠️ If you forget it, your vault **cannot be recovered**
3. Add your first entry with `Ctrl+N`
4. Use the built-in generator for strong passwords
5. Go to **Settings → Data** to import from another password manager

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl + N` | New entry |
| `Ctrl + L` | Lock vault |
| `Ctrl + F` | Focus search |
| `Ctrl + G` | Password generator |
| `Escape` | Close modal / deselect |
| `?` | Show all shortcuts |

---

## Security

VaultGuard uses:
- **Argon2id** for key derivation (memory-hard, GPU/ASIC resistant, `m=65536 t=3 p=4`)
- **AES-256-GCM** for vault encryption with random per-operation nonces
- **HMAC-SHA256** for vault file integrity — any tampering is detected
- **Progressive lockout** — 12h after 10 wrong attempts, 24h, then 1-week cycles
- **Session tokens** — required for all sensitive operations, wiped on lock
- **Memory protection** — keys stored in `Zeroizing` wrappers, wiped on drop
- **Clipboard auto-clear** — configurable timeout, can be set per copy

---

## License

[MIT](./LICENSE) © 2026 Viperzz6988
