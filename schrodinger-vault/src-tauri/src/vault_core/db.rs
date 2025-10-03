use rusqlite::{Connection, Result, params, Row};
use std::path::PathBuf;
use tauri::{Manager, path::BaseDirectory};

/// get the path for the SQLite database in the app's data directory
pub fn db_path(app: &tauri::AppHandle) -> PathBuf {
    app.path()
        .resolve("vault.sqlite", BaseDirectory::AppData)
        .expect("failed to resolve AppData path")
}

/// Return structs for query functions
// TODO: move into seperate file in utils folder (wasn't sure if this was being worked on)
#[derive(serde::Serialize)]
pub struct EntryListItem {
    pub id: i64,
    pub label: String,
    pub username: String,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct NewEntry<'a> {
    pub label: &'a str,
    pub username: &'a str,
    pub notes: Option<&'a str>,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8], // stores plain text for now
}

/// open the database and create schema if needed returing a connection object
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

    // table for the user (only 1 user allowed)
    // this table is the WRONG schema, will be deleted
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user (
            id              INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash   TEXT    NOT NULL,
            salt            BLOB    NOT NULL
            )",
        [],
    )?;

    // Table for entries
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            label       TEXT NOT NULL UNIQUE,
            username    TEXT NOT NULL,
            notes       TEXT,              
            nonce       BLOB NOT NULL,
            ciphertext  BLOB NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )",
        [],
    )?;

    Ok(conn)
}

/// Query functions for entries table
pub fn list_entries(conn: &Connection) -> Result<Vec<EntryListItem>> {
    // Make query statment
    let mut stmt = conn.prepare(
        r#"
        SELECT id, label, username, notes, created_at, updated_at
        FROM entries
        ORDER BY label COLLATE NOCASE
        "#,
    )?; 
    // rows is an iterator, each item is Result<EntryListItem>
    let rows = stmt.query_map([], |row| row_to_list_item(row))?;

    // create vector containing all rows from query
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    // return vecotor of entries
    Ok(out)
}

// Helper, converts db row into EntryListItem
fn row_to_list_item(row: &Row) -> rusqlite::Result<EntryListItem> {
    Ok(EntryListItem {
        id: row.get(0)?,
        label: row.get(1)?,
        username: row.get(2)?,
        notes: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

pub fn add_entry(conn: &Connection, e: NewEntry) -> Result<EntryListItem> {
    conn.execute(
        r#"
        INSERT INTO entries (label, username, notes, nonce, ciphertext)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![e.label, e.username, e.notes, e.nonce, e.ciphertext],
    )?;

    // Prepare to return added entry so it can be displayed in UI immediatly
    let id = conn.last_insert_rowid();
    let mut stmt = conn.prepare(
        r#"
        SELECT id, label, username, notes, created_at, updated_at
        FROM entries
        WHERE id = ?1
        "#,
    )?;

    let item = stmt.query_row(params![id], |row| row_to_list_item(row))?;
    Ok(item)
}

pub fn delete_entry(conn: &Connection, id: i64) -> Result<usize> {
    conn.execute("DELETE FROM entries WHERE id = ?1", params![id]) 
}

// TEMP: for now this just passes plain ciphertext as a string to demo show password function
pub fn temp_get_ciphertext(conn: &Connection, id: i64) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT ciphertext FROM entries WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(0)?;
        Ok(Some(String::from_utf8_lossy(&bytes).to_string()))
    } else {
        Ok(None)
    }
}
