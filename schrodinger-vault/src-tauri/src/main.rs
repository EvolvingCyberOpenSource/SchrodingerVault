// line to hide console window on Windows in release build (doesn't affect other OSes)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// import rust files and folders
mod commands;
mod state;
mod vault_core;

// import rust tools and tauri
use tauri::{self, Manager};

// build and returns the app with plugins and commands with webview
fn build_app() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .setup(|app| { //adding additional setup steps here such as db setup
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
        .invoke_handler(tauri::generate_handler![
            commands::greet,
            commands::add_person,
            commands::list_people,
            commands::user_exists,
            commands::create_vault,
            commands::vault_list,
            commands::vault_add,
            commands::vault_get,
            commands::vault_delete,
            commands::debug_kem_status,
            commands::debug_dump_meta,
            commands::debug_reset_vault_soft,
            commands::debug_reset_vault_hard,
            commands::debug_check_no_aes_in_meta,
            commands::debug_step5_zeroize_print,
            commands::debug_db_path,
            commands::debug_vault_key_status,
        ])
}

// this line just for mobile, ignored on desktop
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // calls build_app function above
    build_app()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// entry point, calls run right above
fn main() { run(); }
