use rusqlite::{Connection, Result};
use std::path::PathBuf;
use tauri::{Manager, path::BaseDirectory};

/// get the path for the SQLite database in the app's data directory
pub fn db_path(app: &tauri::AppHandle) -> PathBuf {
    app.path()
        .resolve("vault.sqlite", BaseDirectory::AppData)
        .expect("failed to resolve AppData path")
}

/// open the database and create schema if needed
pub fn open_and_init(app: &tauri::AppHandle) -> Result<Connection> {
    let path = db_path(app);

    println!("SQLite DB located at: {}", path.display());

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let conn = Connection::open(path)?;

    // test table 
    conn.execute(
        "CREATE TABLE IF NOT EXISTS person (
           id    INTEGER PRIMARY KEY AUTOINCREMENT,
           name  TEXT NOT NULL,
           data  BLOB
         )",
        [],
    )?;

    Ok(conn)
}
