use rusqlite::Connection;
use std::sync::{Arc, Mutex};

/// Holds the app’s shared database connection.
///
/// The connection is stored inside a thread-safe wrapper so it can be
/// safely used by different parts of the app at the same time.
#[derive(Clone)]
pub struct AppDb(pub Arc<Mutex<Connection>>);