//! Secure clipboard operations for VaultGuard.
//!
//! Clipboard writes happen immediately in Rust. Automatic clearing is only
//! scheduled after explicit user confirmation from the frontend.

use std::sync::atomic::{AtomicU64, Ordering};
use tauri::{AppHandle, Emitter};
use tauri_plugin_clipboard_manager::ClipboardExt;

/// Global clipboard timer ID — incremented on copy / clear / reschedule to cancel stale timers.
static CLIPBOARD_TIMER_ID: AtomicU64 = AtomicU64::new(0);

fn cancel_pending_clear() {
    CLIPBOARD_TIMER_ID.fetch_add(1, Ordering::SeqCst);
}

/// Copy text to clipboard and cancel any previously scheduled auto-clear.
pub fn copy_to_clipboard(app: &AppHandle, text: &str) -> Result<(), String> {
    app.clipboard()
        .write_text(text.to_string())
        .map_err(|error| format!("Failed to write to clipboard: {error}"))?;
    cancel_pending_clear();
    Ok(())
}

/// Schedule an auto-clear after the user explicitly opted in.
pub fn schedule_clipboard_clear(app: &AppHandle, timeout_secs: u64) -> Result<(), String> {
    let timer_id = CLIPBOARD_TIMER_ID.fetch_add(1, Ordering::SeqCst) + 1;
    let app_handle = app.clone();

    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(timeout_secs));

        if CLIPBOARD_TIMER_ID.load(Ordering::SeqCst) == timer_id {
            if let Err(error) = clear_clipboard(&app_handle) {
                log::error!(
                    "Failed to auto-clear clipboard after {}s: {}",
                    timeout_secs,
                    error
                );
                return;
            }
            log::info!("Clipboard auto-cleared after {}s", timeout_secs);
            if let Err(error) = app_handle.emit("clipboard-cleared", ()) {
                log::error!("Failed to emit clipboard-cleared event: {}", error);
            }
        }
    });

    app.emit(
        "clipboard-countdown",
        ClipboardCountdown {
            timeout_secs,
            timer_id,
        },
    )
    .map_err(|error| format!("Failed to emit clipboard countdown event: {error}"))?;

    Ok(())
}

/// Clear the clipboard securely and cancel any pending timer.
pub fn clear_clipboard(app: &AppHandle) -> Result<(), String> {
    app.clipboard()
        .write_text(String::new())
        .map_err(|error| format!("Failed to clear clipboard: {error}"))?;
    cancel_pending_clear();
    Ok(())
}

#[derive(Clone, serde::Serialize)]
struct ClipboardCountdown {
    timeout_secs: u64,
    timer_id: u64,
}
