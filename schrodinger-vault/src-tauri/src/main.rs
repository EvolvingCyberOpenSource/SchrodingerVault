// src-tauri/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;
mod vault_core;

use tauri::{self, Manager};

fn build_app() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .setup(|app| {
            // open/create DB in the correct OS AppData dir and create schema if needed
            let conn = crate::vault_core::db::open_and_init(&app.handle())
                .expect("DB init failed");
            // Share the connection with all commands
            app.manage(crate::state::AppDb(std::sync::Arc::new(
                std::sync::Mutex::new(conn),
            )));
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::greet,
            commands::add_person,
            commands::list_people
        ])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    build_app()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() { run(); }
