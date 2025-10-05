// bridges to call Rust commands from JavaScript
const { invoke } = window.__TAURI__.core;

// ********
// demo greet boilerplate (can be removed)
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

const PASS_VIS_DURATION = 10000; // Time till password is hidden (10s)

// --- Password reveal ---
async function showPassword(id, secretSpan, showBtn) {
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
  try {
    const value = await invoke("vault_get", { id });
    await navigator.clipboard.writeText(value);
    setTimeout(async () => {
      try {
        const current_clipboard = await navigator.clipboard.readText();
        if (current_clipboard === value) {
          await navigator.clipboard.writeText("");
        }
      } catch (err) {
        console.log("Clipboard read error: ", err);
      }
    }, PASS_VIS_DURATION);
  } catch (err) {
    console.log("Copy failed:", err);
  }
}

// --- Delete an entry ---
async function deleteEntry(id, row, label) {
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

  const secretSpan = document.createElement("span");
  secretSpan.className = "secret";
  row.appendChild(secretSpan);

  const showBtn = document.createElement("button");
  showBtn.type = "button";
  showBtn.textContent = "Show";
  showBtn.addEventListener("click", () => showPassword(e.id, secretSpan, showBtn));
  row.appendChild(showBtn);

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.textContent = "Copy password";
  copyBtn.addEventListener("click", () => copyPassword(e.id));
  row.appendChild(copyBtn);

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

async function addEntry() {
  const label = labelEl.value;
  const username = usernameEl.value;
  const password = passwordEl.value;
  const notesRaw = notesEl.value;
  const notes = notesRaw.trim().length ? notesRaw : null;

  try {
    await invoke("vault_add", { label, username, password, notes });
    // clear inputs after add
    labelEl.value = "";
    usernameEl.value = "";
    passwordEl.value = "";
    notesEl.value = "";

    // reload list with new entry
    await loadEntries();
  } catch (err) {
    console.log("Error adding entry: ", err);
  }
}


// TODO STEP 3: After implementing VAULT_AES_KEY in unlock_vault,
// use `debug_vault_key_status` as the single source of truth for
// whether the session is unlocked (no client-side flags).
// --- send to create.html if vault not initialized ---
// --- route to create.html (first time) or unlock.html (if vault already initialized))
window.addEventListener("DOMContentLoaded", async () => {
  try {
    // 1) Is vault initialized? If not, go create one.
    const s = await invoke("debug_kem_status"); 
    const initialized = s && (s.sk_exists || s.pk_kem_bytes_len > 0 || s.ct_kem_bytes_len > 0);
    if (!initialized) {
      return window.location.replace("create.html");
    }

    // 2) Is this session unlocked? (Step 3 not implemented yet, so we use sessionStorage)

    // TODO STEP 3: Replace sessionStorage check with a backend check:
    // const { loaded } = await invoke("debug_vault_key_status");
    // if (!loaded) return window.location.replace("unlock.html");
    // After Step 3, remove the sessionStorage fallback entirely.
    const unlocked = sessionStorage.getItem("vault_unlocked") === "1";
    if (!unlocked) {
      return window.location.replace("unlock.html");
    }

    // 3) Good to load entries
    await loadEntries();
  } catch (err) {
    console.error("Init check failed:", err);
    // If anything goes sideways, send to unlock to be safe.
    window.location.replace("unlock.html");
  }
});

// above should be adjusted for step 3 when implemented:
// We’re not setting VAULT_AES_KEY until Step 3, entries page can’t rely on that to know you’re unlocked.(but should for step 3)
//sessionStorage is a temporary session flag set by unlock.js and checked by main.js. 
// It keeps you on the entries page after a successful unlock and clears automatically when the app/window restarts.
