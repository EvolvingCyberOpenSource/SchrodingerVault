use tauri::{command, State};
use rusqlite::params;
use crate::state::AppDb;
use rand::rngs::OsRng;
use rand::RngCore;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

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

#[command]
pub fn create_vault(db: State<AppDb>, master_password: String) -> Result<bool, String> {
    println!("In create_vault...");
    println!("(debug) received password len = {}", master_password.len()); // temp, remove later. shouldnt be logging 

    // connection to db
    let mut conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;

    // intiazling and filling salts with random bytes
    let mut salt_pw  = [0u8; 16];
    let mut salt_kdf = [0u8; 32];
    OsRng.fill_bytes(&mut salt_pw);
    OsRng.fill_bytes(&mut salt_kdf);

    // encode for TEXT storage
    let salt_pw_b64  = B64.encode(salt_pw);
    let salt_kdf_b64 = B64.encode(salt_kdf);

    // choosing kdf algorithim and parameters (choosing FIPS compliant)
    let kdf = "pbkdf2-hmac-sha256";
    let kdf_params = r#"{"iterations":310000,"out":32,"algo":"sha256"}"#;


    // making stretch password hash with pbkdf2
    let iterations: u32 = 310_000; // number of iterations (310,000) we will use as a parameter
    let mut k1 = [0u8; 32]; // initializing k1 in memory to hold the stretched key

    // uses pbkdf2 algorithm to fill k1 with the stretched key in RAM using the password and salt
    pbkdf2_hmac::<Sha256>(
        master_password.as_bytes(), 
        &salt_pw, 
        iterations.into(), 
        &mut k1
    );

    // TODO: device secret part starts here

    // storing both salts and kdf and params in meta table as their own entires
    // currenttly we are doing INSERT OR REPLACE so final version should remove replace option
    // (instructions say to create meta table during inseration but we created it during db init so will have to change that later)
    {
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"salt_pw",  &salt_pw_b64),
        ).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"salt_kdf", &salt_kdf_b64),
        ).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"kdf", kdf),
        ).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (&"kdf_params", kdf_params),
        ).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
    }


    println!("(debug) salts and kdf info stored in meta table, returning...");

    Ok(true)
}
