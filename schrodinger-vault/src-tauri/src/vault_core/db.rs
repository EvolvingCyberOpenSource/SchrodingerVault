use rusqlite::{Connection, Result, params, Row};
use std::path::PathBuf;
use tauri::{Manager, path::BaseDirectory};


/// Resolves the full path to the `vault.sqlite` database file.
///
/// # Arguments
/// * `app` - a handle to the running Tauri application
///
/// # Returns
/// The path to where the database file will be located on the system
pub fn db_path(app: &tauri::AppHandle) -> PathBuf {
    app.path()
        .resolve("vault.sqlite", BaseDirectory::AppData)
        .expect("failed to resolve AppData path")
}

/// Return structs for query functions
// TODO: move into separate file in utils folder
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
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8],
}

#[derive(serde::Serialize)]
pub struct EncEntry {
    pub label: String,
    pub username: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}


/// open the database and create schema if needed returning a connection object
pub fn open_and_init(app: &tauri::AppHandle) -> Result<Connection> {
    let path = db_path(app);

    // TODO: can get rid of this debug in the future
    println!("SQLite DB located at: {}", path.display());

    // saftey check to ensure the directory where the db will be exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // creates the database file (if it doesn't exist)
    let conn = Connection::open(path)?;

    // Good defaults for desktop apps (requires rusqlite >= 0.29)
    let _ = conn.pragma_update(None, "journal_mode", &"WAL");
    let _ = conn.pragma_update(None, "synchronous", &"FULL");

    // Needed by create_vault()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    // test table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS person (
           id    INTEGER PRIMARY KEY AUTOINCREMENT,
           name  TEXT NOT NULL,
           data  BLOB
         )",
        [],
    )?;

    // table for the user (legacy demo; to be deleted later)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user (
            id              INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash   TEXT    NOT NULL,
            salt            BLOB    NOT NULL
        )",
        [],
    )?;

    // TODO: remove later and replace with correct schema in another function and call that here instead
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            label       TEXT NOT NULL UNIQUE,
            username    TEXT NOT NULL,
            notes       TEXT,
            nonce       BLOB NOT NULL,
            ciphertext  BLOB NOT NULL,
            tag         BLOB NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )",
        [],
    )?;

    // Helpful index for listing/search
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_entries_label ON entries(label)",
        [],
    )?;

    Ok(conn)
}


/// Query functions for entries table.
///
/// # Arguments
/// * `conn` - connection to the SQLite database
///
/// # Returns
/// A vector of `EntryListItem` structs representing all entries in the entry table
pub fn list_entries(conn: &Connection) -> Result<Vec<EntryListItem>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, label, username, notes, created_at, updated_at
        FROM entries
        ORDER BY label COLLATE NOCASE
        "#,
    )?;
    let rows = stmt.query_map([], |row| row_to_list_item(row))?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
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
        INSERT INTO entries (label, username, notes, nonce, ciphertext, tag)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![e.label, e.username, e.notes, e.nonce, e.ciphertext, e.tag],
    )?;

    // Prepare to return added entry so it can be displayed in UI immediately
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


pub fn get_entry_encrypted(conn: &Connection, id: i64) -> Result<Option<EncEntry>> {
    let mut stmt = conn.prepare(
        "SELECT label, username, nonce, ciphertext, tag FROM entries WHERE id = ?1"
    )?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(EncEntry {
            label: row.get(0)?,
            username: row.get(1)?,
            nonce: row.get(2)?,
            ciphertext: row.get(3)?,
            tag: row.get(4)?,
        }))
    } else {
        Ok(None)
    }
}

