use tauri::{command, State};
use rusqlite::params;
use crate::state::AppDb;

// default teast command
#[command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

// person struct for the example commands
// note: we should probaly moves structs in a separate file in a utils folder
#[derive(serde::Serialize)]
pub struct Person { pub id: i32, pub name: String }

//TODO: add error handling, authentication 'middleware, and move queries to db.rs

//function called to add a person to the database
#[command]
pub fn add_person(db: State<AppDb>, name: String) -> Result<(), String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?; // <-- use inner()
    conn.execute("INSERT INTO person (name, data) VALUES (?1, NULL)", params![name])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[command]
pub fn user_exists(db: State<AppDb>) -> Result<bool, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let count: i64 = conn
        .query_row("SELECT COUNT(1) FROM user WHERE id = 1", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    Ok(count > 0)
}

#[command]
pub fn list_people(db: State<AppDb>) -> Result<Vec<Person>, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?; // <-- use inner()
    let mut stmt = conn.prepare("SELECT id, name FROM person ORDER BY id")
        .map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        Ok(Person { id: row.get(0)?, name: row.get(1)? })
    }).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for r in rows { out.push(r.map_err(|e| e.to_string())?); }
    Ok(out)
}
