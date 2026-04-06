<div align="center">
  <img src="src/assets/VaultGuardV3.png" width="120" alt="VaultGuard">

  # VaultGuard

  A fast, secure, local-first password manager.
  Built with Tauri and Rust. Your vault never leaves your device.

  ![License](https://img.shields.io/badge/license-MIT-blue)
  ![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
</div>

---

## Download

**No installation of Rust required. Just download and run.**

| Platform | File | |
|---|---|---|
| Linux (Debian/Ubuntu/Mint) | `VaultGuard_0.1.0_amd64.deb` | [Download →](https://github.com/Viperzz6988/VaultGuard/releases/latest) |
| Linux (Fedora/RHEL) | `VaultGuard-0.1.0.x86_64.rpm` | [Download →](https://github.com/Viperzz6988/VaultGuard/releases/latest) |
| Linux (any distro) | `VaultGuard_0.1.0_amd64.AppImage` | [Download →](https://github.com/Viperzz6988/VaultGuard/releases/latest) |
| Windows | `VaultGuard_0.1.0_x64_en-US.msi` | [Download →](https://github.com/Viperzz6988/VaultGuard/releases/latest) |

### Linux install

```bash
# Debian/Ubuntu/Mint:
sudo dpkg -i VaultGuard_*.deb

# Fedora/RHEL:
sudo rpm -i VaultGuard-*.rpm

# Any distro (AppImage — no install needed):
chmod +x VaultGuard_*.AppImage
./VaultGuard_*.AppImage

# Arch Linux:
# Install debtap first: sudo pacman -S debtap
# Then: debtap VaultGuard_*.deb && sudo pacman -U *.pkg.tar.*
```

### Windows install

Double-click the `.msi` file. VaultGuard will appear in your Start Menu.

---

## Features

- 🔒 AES-256-GCM encrypted vault — Argon2id key derivation
- 🚫 No cloud, no accounts, no telemetry — 100% local
- 🔑 Strong master password enforcement (15+ chars, mixed case, numbers, symbols)
- 🛡 Progressive brute-force lockout after failed attempts
- 📋 Clipboard auto-clear with confirmation popup
- 🗂 Categories: Login, API Keys, Other + custom categories
- 🔍 Real-time search, password generator, strength meter
- 📥 Import: Bitwarden JSON, KeePass XML, 1Password CSV, LastPass CSV
- 📤 Export: Encrypted backup, KeePass XML, Bitwarden JSON
- 🌙 Dark/light theme, English/German

---

## First Launch

1. Open VaultGuard from your app launcher or Start Menu
2. Create a master password — it must have:
   - At least 15 characters
   - Uppercase + lowercase letters
   - At least one number
   - At least one special character (!@#$...)
3. ⚠️ **This password is never stored anywhere.** If you forget it, your vault cannot be recovered.
4. Add entries with `Ctrl+N`

---

## Build from source (optional)

Only needed if you want to modify the code.

**Requirements:** [Rust](https://rustup.rs) + `cargo install tauri-cli`

**Linux system dependencies:**
```bash
# Debian/Ubuntu:
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev

# Fedora:
sudo dnf install webkit2gtk4.1-devel gtk3-devel

# Arch:
sudo pacman -S webkit2gtk base-devel
```

```bash
git clone https://github.com/Viperzz6988/VaultGuard
cd VaultGuard
cargo tauri build
./install.sh
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+N` | New entry |
| `Ctrl+L` | Lock vault |
| `Ctrl+F` | Focus search |
| `Ctrl+G` | Generator |
| `Escape` | Close modal |

---

## Security

- Argon2id key derivation (`m=65536, t=3, p=4`) — memory-hard, GPU-resistant
- AES-256-GCM encryption with random per-operation nonces
- HMAC-SHA256 vault file integrity — tampering detected on every load
- Session tokens required for all vault operations
- Keys stored in `Zeroizing<>` — wiped from memory on lock
- Clipboard auto-cleared on lock and app close

---

## License

[MIT](./LICENSE) © 2026 Viperzz6988
