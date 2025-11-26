// line to hide console window on Windows in release build (doesn't affect other OSes)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// import rust files and folders
mod commands;
mod state;
mod vault_core;
mod error;

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
            let conn = crate::vault_core::db::open_and_init(&app.handle())
                .expect("DB init failed");
            // share the connection with all commands and create current state for the app
            app.manage(crate::state::AppDb(std::sync::Arc::new(
                std::sync::Mutex::new(conn),
            )));
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::greet,
            commands::add_person,
            commands::list_people,
            commands::user_exists,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::vault_list,
            commands::vault_add,
            commands::vault_get,
            commands::vault_delete,
            commands::copy_to_clipboard,
            #[cfg(target_os = "windows")]
            commands::copy_to_clipboard_no_history,
            commands::get_clipboard_text,
            commands::debug_kem_status,
            commands::debug_dump_meta,
            commands::debug_reset_vault_soft,
            commands::debug_reset_vault_hard,
            commands::debug_check_no_aes_in_meta,
            commands::debug_step5_zeroize_print,
            commands::debug_db_path,
            commands::debug_vault_key_status,
            commands::debug_list_schema,
            commands::debug_decapsulate_status,
            commands::debug_aes_key_exists,
            commands::debug_zeroize_aes_key,
            commands::debug_entry_blob_info,
            commands::debug_tamper_entry,
            commands::debug_crypto_selftest,
            commands::setup_verifier,
            commands::debug_insert_bad_entry,
            commands::debug_delete_device_key,
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
            tauri::RunEvent::ExitRequested { api, .. } => {
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
fn main() { run(); }
