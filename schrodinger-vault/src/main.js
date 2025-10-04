// bridges to call Rust commands from JavaScript
const { invoke } = window.__TAURI__.core;


// ********
// this block of code can be deleted, its just boilerplate to test calling rust commands
// but its a good example of how a call to rust works
let greetInputEl;
let greetMsgEl;
greetInputEl = document.querySelector("#greet-input");
greetMsgEl = document.querySelector("#greet-msg");
document.querySelector("#greet-form").addEventListener("submit", (e) => {
  e.preventDefault();
  greet();
});
async function greet() {
  greetMsgEl.textContent = await invoke("greet", { name: greetInputEl.value });
}
// ********


const PASS_VIS_DURATION = 10000   // Time till password is hidden (10s)
// --- Password reveal ---
async function showPassword(id, secretSpan, showBtn) {
  // TODO: find best way to clear revealed password variable from memory
  try {
    showBtn.disabled = true;
    const value = await invoke("vault_get", { id });
    secretSpan.textContent = `  ${value}`;
    // auto-hide
    setTimeout(() => {
      secretSpan.textContent = "";
      showBtn.disabled = false;
    }, PASS_VIS_DURATION);
  } catch (err) {
    console.log("Show failed:", err);
    showBtn.disabled = false;
  }
}

// --- Copy password ---
async function copyPassword(id) {
  // This should write to and clear the clipboard but may not work depending on sys settings
  try {
    const value = await invoke("vault_get", { id });
    await navigator.clipboard.writeText(value);
    setTimeout(async () => {
      try {
        // Only clear if user hasn't changed clipboard
        const current_clipboard = await navigator.clipboard.readText();
        if (current_clipboard === value) {
          await navigator.clipboard.writeText("");
        }
      } catch {
        console.log("Clipboard read error: ", err);
      }
    }, PASS_VIS_DURATION);
  } catch (err) {
    console.log("Copy failed:", err);
  }
}

// --- Delete an entry ---
async function deleteEntry(id, row, label) {
  // Ask user to confirm delete
  const ok = confirm(`Delete "${label}"?`);
  if (!ok) return;
  try {
    await invoke("vault_delete", { id });
    row.remove();
  } catch (err) {
    console.log("Delete failed:", err);
  }
}

// --- Make entry row ---
function renderRow(e) {
  const row = document.createElement("div");
  row.className = "entry-row";
  row.textContent = `${e.label} — ${e.username}${e.notes ? " — " + e.notes : ""}`;

  // show button
  const secretSpan = document.createElement("span");
  secretSpan.className = "secret";
  row.appendChild(secretSpan);

  const showBtn = document.createElement("button");
  showBtn.type = "button";
  showBtn.textContent = "Show";
  showBtn.addEventListener("click", () => showPassword(e.id, secretSpan, showBtn));
  row.appendChild(showBtn);

  // Copy button
  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.textContent = "Copy password";
  copyBtn.addEventListener("click", () => copyPassword(e.id));
  row.appendChild(copyBtn);

  // Delete button
  const delBtn = document.createElement("button");
  delBtn.type = "button";
  delBtn.textContent = "Delete";
  delBtn.addEventListener("click", () => deleteEntry(e.id, row, e.label));
  row.appendChild(delBtn);

  return row;
}

// --- Load all entries into html list ---
async function loadEntries() {
  const container = document.getElementById("entry-list");
  try {
    const items = await invoke("vault_list");
    container.innerHTML = "";

    if (!items || items.length === 0) {
      container.textContent = "No entries yet.";
      return;
    }

    for (const e of items) {
      container.appendChild(renderRow(e));
    }
  } catch (err) {
    console.log("Error fetching list of entries:", err);
  }
}

// --- Add a new entry ---
let labelEl;
let usernameEl;
let passwordEl;
let notesEl;
labelEl = document.querySelector("#label");
usernameEl = document.querySelector("#username");
passwordEl = document.querySelector("#password");
notesEl = document.querySelector("#notes");
document.querySelector("#add-entry").addEventListener("submit", (e) => {
  e.preventDefault();
  addEntry();
});

async function addEntry(params) {
  const label = labelEl.value;
  const username = usernameEl.value;
  const password = passwordEl.value;
  const notesRaw = notesEl.value;
  const notes = notesRaw.trim().length ? notesRaw : null;

  try {
    await invoke("vault_add", { label, username, password, notes});
    // clear inputs after add
    labelEl.value = "";
    usernameEl.value = "";
    passwordEl.value = "";
    notesEl.value = "";

    // reload list with new entry
    await loadEntries();
  } catch (err) {
    console.log("Error adding entry: ", err)
  }
  
}


/**
 * Calls Rust function `user_exists` to query the database if a user exists.
 *
 * @returns {boolean} true if user exists, false otherwise
 */
async function userExists(){

  console.log("Checking if user exists...");
  try {

    const userExists = await invoke("user_exists"); // invoke rust command
    console.log("User exists:", userExists);
    return userExists;

  } catch (err) {

    console.log("Error checking user existence:", err);
    return false;
  
  }
}

// this is immediately called when the web page is loaded
window.addEventListener("DOMContentLoaded", async () => {

  window.location.replace("unlock.html");

  // check if a user even exists
  // if not, redirect to create password/vault page
  // const exists = await userExists();
  // if (!exists){
  //   window.location.replace("create.html");
  // } 
});
