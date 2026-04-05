#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$ROOT_DIR/src-tauri/target/release/bundle"
BINARY_PATH="$ROOT_DIR/src-tauri/target/release/vaultguard"
LOCAL_BIN_DIR="$HOME/.local/bin"
LOCAL_APP_DIR="$HOME/.local/share/applications"
LOCAL_ICON_ROOT="$HOME/.local/share/icons/hicolor"
LOCAL_DESKTOP_FILE="$LOCAL_APP_DIR/vaultguard.desktop"
APPIMAGE_DEST="$LOCAL_BIN_DIR/vaultguard.AppImage"
APPIMAGE_LINK="$LOCAL_BIN_DIR/vaultguard"

require_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "install.sh is Linux-only. See README.md for Windows installation instructions."
    exit 1
  fi
}

require_cargo() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: Rust/Cargo not found. Install rustup from https://rustup.rs and re-run."
    exit 1
  fi
}

require_tauri_cli() {
  if ! cargo tauri --help >/dev/null 2>&1; then
    echo "Error: cargo-tauri not found. Install it with: cargo install tauri-cli"
    exit 1
  fi
}

find_latest() {
  local directory="$1"
  local pattern="$2"

  if [[ ! -d "$directory" ]]; then
    return 0
  fi

  find "$directory" -maxdepth 2 -type f -iname "$pattern" 2>/dev/null | sort | tail -n 1
}

run_privileged() {
  if command -v pkexec >/dev/null 2>&1; then
    pkexec "$@"
    return $?
  fi

  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return $?
  fi

  return 1
}

refresh_desktop_caches() {
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$LOCAL_APP_DIR" >/dev/null 2>&1 || true
  fi

  if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$LOCAL_ICON_ROOT" >/dev/null 2>&1 || true
  fi
}

write_local_desktop_file() {
  mkdir -p "$LOCAL_APP_DIR"

  cat >"$LOCAL_DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=VaultGuard
Comment=Local-first password manager
Exec=$1
Icon=vaultguard
Type=Application
Categories=Utility;Security;
StartupWMClass=VaultGuard
MimeType=
EOF
}

install_icons() {
  local size
  for size in 16 32 48 64 128 256; do
    mkdir -p "$LOCAL_ICON_ROOT/${size}x${size}/apps"
    cp "$ROOT_DIR/src-tauri/icons/${size}x${size}.png" \
      "$LOCAL_ICON_ROOT/${size}x${size}/apps/vaultguard.png"
  done
}

install_binary_local() {
  if [[ ! -x "$BINARY_PATH" ]]; then
    echo "Local install fallback needs the built binary at $BINARY_PATH."
    return 1
  fi

  mkdir -p "$LOCAL_BIN_DIR"
  cp "$BINARY_PATH" "$LOCAL_BIN_DIR/vaultguard"
  chmod +x "$LOCAL_BIN_DIR/vaultguard"
  install_icons
  write_local_desktop_file "$HOME/.local/bin/vaultguard"
  refresh_desktop_caches
  return 0
}

install_appimage_local() {
  local appimage="$1"
  if [[ -z "$appimage" || ! -f "$appimage" ]]; then
    return 1
  fi

  mkdir -p "$LOCAL_BIN_DIR"
  cp "$appimage" "$APPIMAGE_DEST"
  chmod +x "$APPIMAGE_DEST"
  ln -sf "$APPIMAGE_DEST" "$APPIMAGE_LINK"
  install_icons
  write_local_desktop_file "$HOME/.local/bin/vaultguard"
  refresh_desktop_caches
  return 0
}

detect_distro() {
  if [[ -n "${VAULTGUARD_DISTRO_OVERRIDE:-}" ]]; then
    case "$VAULTGUARD_DISTRO_OVERRIDE" in
      arch|debian|fedora|generic)
        printf '%s\n' "$VAULTGUARD_DISTRO_OVERRIDE"
        return 0
        ;;
      *)
        printf 'generic\n'
        return 0
        ;;
    esac
  fi

  local id=""
  local id_like=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    id="${ID:-}"
    id_like="${ID_LIKE:-}"
  fi

  case " $id $id_like " in
    *" arch "*)
      printf 'arch\n'
      ;;
    *" debian "*|*" ubuntu "*|*" mint "*)
      printf 'debian\n'
      ;;
    *" fedora "*|*" rhel "*|*" suse "*|*" opensuse "*)
      printf 'fedora\n'
      ;;
    *)
      printf 'generic\n'
      ;;
  esac
}

ensure_bundles() {
  if [[ -d "$BUNDLE_DIR" ]] && find "$BUNDLE_DIR" -mindepth 1 -maxdepth 3 -type f | read -r _; then
    return 0
  fi

  echo "Building VaultGuard — this may take a few minutes..."
  (
    cd "$ROOT_DIR/src-tauri" &&
      cargo tauri build
  )
}

install_deb() {
  local deb_bundle="$1"
  [[ -n "$deb_bundle" && -f "$deb_bundle" ]] || return 1
  command -v dpkg >/dev/null 2>&1 || return 1
  run_privileged dpkg -i "$deb_bundle"
}

install_rpm() {
  local rpm_bundle="$1"
  [[ -n "$rpm_bundle" && -f "$rpm_bundle" ]] || return 1
  command -v rpm >/dev/null 2>&1 || return 1
  run_privileged rpm -i "$rpm_bundle"
}

install_arch() {
  local deb_bundle="$1"
  local appimage_bundle="$2"

  if [[ -n "$deb_bundle" && -f "$deb_bundle" ]] && command -v debtap >/dev/null 2>&1 && command -v pacman >/dev/null 2>&1; then
    local temp_dir package_path
    temp_dir="$(mktemp -d)"
    cp "$deb_bundle" "$temp_dir/"
    (
      cd "$temp_dir" &&
        debtap -q "$(basename "$deb_bundle")"
    ) || true
    package_path="$(find_latest "$temp_dir" '*.pkg.tar.*')"
    if [[ -n "$package_path" && -f "$package_path" ]] && run_privileged pacman -U --noconfirm "$package_path"; then
      rm -rf "$temp_dir"
      return 0
    fi
    rm -rf "$temp_dir"
  fi

  if install_appimage_local "$appimage_bundle"; then
    return 0
  fi

  install_binary_local
}

main() {
  require_linux
  require_cargo
  require_tauri_cli

  if ! ensure_bundles; then
    exit 1
  fi

  local distro deb_bundle rpm_bundle appimage_bundle
  distro="$(detect_distro)"
  deb_bundle="$(find_latest "$BUNDLE_DIR/deb" 'vaultguard_*.deb')"
  rpm_bundle="$(find_latest "$BUNDLE_DIR/rpm" 'vaultguard-*.rpm')"
  appimage_bundle="$(find_latest "$BUNDLE_DIR/appimage" '*.AppImage')"

  case "$distro" in
    debian)
      echo "Using Debian-like install path."
      if ! install_deb "$deb_bundle"; then
        echo "Package install unavailable or failed; falling back to local binary install."
        install_binary_local || return 1
      fi
      ;;
    fedora)
      echo "Using Fedora/RHEL/openSUSE install path."
      if ! install_rpm "$rpm_bundle"; then
        echo "Package install unavailable or failed; falling back to local binary install."
        install_binary_local || return 1
      fi
      ;;
    arch)
      echo "Using Arch install path."
      install_arch "$deb_bundle" "$appimage_bundle" || return 1
      ;;
    generic)
      echo "Using generic local install path."
      install_binary_local || return 1
      ;;
  esac

  echo "VaultGuard installed. Launch it from your app launcher or run: vaultguard"
}

main "$@"
