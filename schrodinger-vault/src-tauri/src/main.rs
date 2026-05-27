// line to hide console window on Windows in release build (doesn't affect other OSes)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// import rust files and folders
mod commands;
mod state;
mod vault_core;

// import rust tools and tauri
use tauri::{self, Manager};

// import panic for locking the vault on crash
use std::panic;

// import ctrlc for locking vault on command line termination
use ctrlc;

fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        eprintln!("Application panicked: {info}");
        commands::lock_vault();
        let default_hook = panic::take_hook();
        default_hook(info);
    }));
}

/// Builds the Tauri app and sets everything up.
///
/// This function creates the main Tauri application builder.  
/// It runs setup code to open the database, store the connection so other
/// commands can use it, adds the opener plugin, and registers all the app’s
/// command functions.
///
/// # Returns
/// A ready to run Tauri app builder.
fn build_app() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .setup(|app| {
            // create a connection to the database calling the function in vault_core/db.rs
            let conn = crate::vault_core::db::open_and_init(&app.handle()).expect("DB init failed");
            // share the connection with all commands and create current state for the app
            app.manage(crate::state::AppDb(std::sync::Arc::new(
                std::sync::Mutex::new(conn),
            )));
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::vault_exists,
            commands::create_vault,
            commands::unlock_vault,
            commands::change_master_password,
            commands::key_derivation_status,
            commands::change_key_derivation_mode,
            commands::lock_vault,
            commands::vault_list,
            commands::vault_add,
            commands::vault_update,
            commands::vault_get,
            commands::vault_delete,
            commands::commands_clipboard::copy_to_clipboard,
            commands::commands_clipboard::copy_secret_to_clipboard,
            #[cfg(target_os = "windows")]
            commands::commands_clipboard::copy_to_clipboard_no_history,
            commands::commands_clipboard::get_clipboard_text,
            commands::vault_session_status,
            #[cfg(debug_assertions)]
            commands::debug_kem_status,
            #[cfg(debug_assertions)]
            commands::debug_dump_meta,
            #[cfg(debug_assertions)]
            commands::debug_reset_vault_soft,
            #[cfg(debug_assertions)]
            commands::debug_reset_vault_hard,
            #[cfg(debug_assertions)]
            commands::debug_check_no_aes_in_meta,
            #[cfg(debug_assertions)]
            commands::debug_step5_zeroize_print,
            #[cfg(debug_assertions)]
            commands::debug_hkdf_step5_zeroize_demo,
            #[cfg(debug_assertions)]
            commands::debug_db_path,
            #[cfg(debug_assertions)]
            commands::debug_vault_key_status,
            #[cfg(debug_assertions)]
            commands::debug_list_schema,
            #[cfg(debug_assertions)]
            commands::debug_decapsulate_status,
            #[cfg(debug_assertions)]
            commands::debug_aes_key_exists,
            #[cfg(debug_assertions)]
            commands::debug_zeroize_aes_key,
            #[cfg(debug_assertions)]
            commands::debug_entry_blob_info,
            #[cfg(debug_assertions)]
            commands::debug_tamper_entry,
            #[cfg(debug_assertions)]
            commands::debug_crypto_selftest,
            #[cfg(debug_assertions)]
            commands::debug_insert_bad_entry,
            #[cfg(debug_assertions)]
            commands::debug_delete_device_key,
            #[cfg(debug_assertions)]
            commands::debug_corrupt_manifest,
            commands::factory_reset_vault,
        ])
}

/// Launches the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // installing panic hook
    install_panic_hook();

    // call lock_vault on ctrl+c from command line
    ctrlc::set_handler(|| {
        println!("Received termination signal — locking vault...");
        commands::lock_vault();
    })
    .expect("Error setting Ctrl-C handler");

    // calls build_app function above to build the application then runs it
    build_app()
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|_app_handle, event| match event {
            tauri::RunEvent::ExitRequested { api: _, .. } => {
                println!("App exit requested — cleaning up...");
                commands::lock_vault();
            }
            tauri::RunEvent::Exit => {
                commands::lock_vault();
                println!("App exited.");
            }
            tauri::RunEvent::WindowEvent { event, .. } => {
                if let tauri::WindowEvent::Destroyed = event {
                    println!("Window destroyed — locking vault...");
                    commands::lock_vault();
                }
            }
            _ => {}
        });
}

// entry point, calls run right above
fn main() {
    run();
}
