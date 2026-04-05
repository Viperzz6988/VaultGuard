//! VaultGuard — Secure Password Manager
//!
//! Core library module that ties together all subsystems and registers
//! Tauri commands. This is the Rust entry point for the Tauri application.

mod clipboard;
mod commands;
mod crypto;
mod error;
mod models;
mod security;
mod vault;

use std::sync::Mutex;
use tauri::Manager;

#[cfg(target_os = "windows")]
fn apply_windows_process_hardening() {
    use std::mem::size_of;
    use winapi::um::processthreadsapi::SetProcessMitigationPolicy;
    use winapi::um::winnt::{
        ProcessASLRPolicy, ProcessDEPPolicy, PROCESS_MITIGATION_ASLR_POLICY,
        PROCESS_MITIGATION_DEP_POLICY,
    };

    // SAFETY: The mitigation structs are initialized locally and passed with the
    // correct size to the documented Windows API for the current process only.
    unsafe {
        let mut dep_policy: PROCESS_MITIGATION_DEP_POLICY = std::mem::zeroed();
        dep_policy.set_Enable(1);
        dep_policy.set_DisableAtlThunkEmulation(1);
        let dep_ok = SetProcessMitigationPolicy(
            ProcessDEPPolicy,
            &mut dep_policy as *mut _ as *mut _,
            size_of::<PROCESS_MITIGATION_DEP_POLICY>(),
        );
        if dep_ok == 0 {
            log::warn!("Failed to enable DEP process mitigation");
        }

        let mut aslr_policy: PROCESS_MITIGATION_ASLR_POLICY = std::mem::zeroed();
        aslr_policy.set_EnableBottomUpRandomization(1);
        aslr_policy.set_EnableForceRelocateImages(1);
        aslr_policy.set_EnableHighEntropy(1);
        aslr_policy.set_DisallowStrippedImages(1);
        let aslr_ok = SetProcessMitigationPolicy(
            ProcessASLRPolicy,
            &mut aslr_policy as *mut _ as *mut _,
            size_of::<PROCESS_MITIGATION_ASLR_POLICY>(),
        );
        if aslr_ok == 0 {
            log::warn!("Failed to enable ASLR process mitigation");
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn apply_windows_process_hardening() {}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize logger
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    // Apply security hardening
    security::disable_core_dumps();
    security::disable_ptrace_attach();
    apply_windows_process_hardening();

    #[cfg(unix)]
    {
        // SAFETY: `getuid` reads the effective user ID of the current process.
        if unsafe { libc::getuid() } == 0 {
            log::warn!("Running VaultGuard as root is not recommended.");
        }
    }

    // Determine vault path
    let vault_path = match vault::vault_path() {
        Ok(path) => path,
        Err(error) => {
            log::error!("Failed to determine vault path: {}", error);
            return;
        }
    };

    if std::env::args().any(|argument| argument == "--reset-integrity") {
        match security::reset_integrity_manifest(&vault_path) {
            Ok(()) => log::info!("VaultGuard integrity manifest refreshed."),
            Err(error) => log::error!("Failed to reset integrity manifest: {}", error),
        }
        return;
    }

    // Initialize application state
    let app_state = commands::AppState::new(vault_path);

    let run_result = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(Mutex::new(app_state))
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                let _ = crate::clipboard::clear_clipboard(window.app_handle());
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::dialog_open_file,
            commands::dialog_save_file,
            commands::get_startup_integrity_status,
            commands::configure_file_protection,
            commands::quit_app,
            // Vault lifecycle
            commands::check_vault_exists,
            commands::check_vault_unlocked,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::get_brute_force_status,
            commands::get_vault_file_status,
            // Entries
            commands::get_entries,
            commands::get_entry,
            commands::create_entry,
            commands::update_entry,
            commands::reorder_entries,
            commands::move_entry_to_category,
            commands::reorder_entry,
            commands::delete_entry,
            commands::restore_entry,
            commands::permanent_delete,
            commands::get_trash,
            // Categories
            commands::get_categories,
            commands::create_category,
            commands::update_category,
            commands::reorder_categories,
            commands::delete_category,
            // Password tools
            commands::generate_password,
            commands::generate_passphrase,
            commands::check_password_strength,
            // Clipboard
            commands::copy_to_clipboard,
            commands::schedule_clipboard_clear,
            commands::clear_clipboard,
            commands::open_url,
            // Settings
            commands::get_settings,
            commands::update_settings,
            // Master password
            commands::change_master_password,
            // Import/Export
            commands::import_vault_data,
            commands::export_vault_data,
            commands::export_vault_json,
            commands::export_keepass_xml,
            commands::export_backup,
            commands::restore_last_good_backup,
            commands::import_bitwarden_json,
            commands::import_csv,
            commands::import_keepass_xml,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = run_result {
        log::error!("Error while running VaultGuard: {}", error);
    }
}
