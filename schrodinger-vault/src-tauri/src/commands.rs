use tauri::{command, State};
use rusqlite::params;
use crate::state::AppDb;
use crate::vault_core::db::{self, EntryListItem, NewEntry};

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

/// Input validation 
// TODO: we may want to change some of these specifics later

fn validate_label(label: &str) -> Result<String, String> {
    let trimmed_label = label.trim();
    if trimmed_label.is_empty() { return Err("Label is required".into()); }
    if trimmed_label.len() > 128 { return Err("Label is too long (max 128)".into()); }
    Ok(trimmed_label.to_string())
}

fn validate_username(username: &str) -> Result<String, String> {
    let trimmed_username = username.trim();
    if trimmed_username.is_empty() { return Err("Username is required".into()); }
    if trimmed_username.len() > 256 { return Err("Username is too long (max 256)".into()); }
    Ok(trimmed_username.to_string())
}

fn validate_password(password: &str) -> Result<String, String> {
    if password.is_empty() { return Err("Password is required".into()); }
    if password.len() > 10000 { return Err("Password is too long".into()); }
    Ok(password.to_string())
}

fn validate_notes(opt: &Option<String>) -> Result<Option<String>, String> {
    if let Some(notes) = opt {
        let trimmed_notes = notes.trim();
        if trimmed_notes.len() > 2_000 {
            return Err("Notes are too long (max 2000)".into());
        }
        if trimmed_notes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed_notes.to_string()))
        }
    } else {
        Ok(None)
    }
}


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

#[command]
pub fn vault_list(db: State<AppDb>) -> Result<Vec<EntryListItem>, String> {
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    db::list_entries(&conn).map_err(|e| e.to_string())
}

#[command]
pub fn vault_add(db: State<AppDb>, label: String, username: String, password: String, notes: Option<String>,
) -> Result<EntryListItem, String> {
    let label = validate_label(&label)?;
    let username = validate_username(&username)?;
    let password = validate_password(&password)?;
    let notes = validate_notes(&notes)?;

    // TEMP: place holder nonce and ciphertext fields
    let nonce = [0u8; 12];
    let ciphertext_bytes = password.into_bytes();

    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let new = NewEntry {
        label: &label,
        username: &username,
        notes: notes.as_deref(),
        nonce: &nonce,
        ciphertext: &ciphertext_bytes,
    };
    db::add_entry(&conn, new).map_err(|e| e.to_string())
}

#[command]
pub fn vault_get(db: State<AppDb>, id: i64) -> Result<String, String> {
    if id <= 0 {
        return Err("Invalid id".into());
    }
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    match db::temp_get_ciphertext(&conn, id) {
        Ok(Some(secret)) => Ok(secret),
        Ok(None) => Err("No entry found with that id".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[command]
pub fn vault_delete(db: State<AppDb>, id: i64) -> Result<(), String> {
    if id <= 0 { 
        return Err("Invalid id".into());
    }
    let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
    let n = db::delete_entry(&conn, id).map_err(|e| e.to_string())?;
    if n == 0 {
        Err("No entry found with that id".into()) 
    } else { 
        Ok(())
    }
}
