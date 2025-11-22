// bridges to call Rust commands from JavaScript
const { invoke } = window.__TAURI__.core;
const { ask } = window.__TAURI__.dialog;

const PASS_VIS_DURATION = 10000; // Time till password is hidden (10s)
const BULLETS = "••••••••";

// single clipboard timer and owner token
let clipboardClearTimer = null;
let clipboardOwnerToken = 0;

// --- Password reveal ---
async function showPassword(id, secretSpan, showBtn) {
    try {
        showBtn.disabled = true;
        const value = await invoke("vault_get", { id });
        secretSpan.textContent = value;
        // auto-hide
        setTimeout(() => {
            secretSpan.textContent = BULLETS;
            showBtn.disabled = false;
        }, PASS_VIS_DURATION);
    } catch (err) {
        console.log("Show failed:", err);
        showBtn.disabled = false;
    }
}

// -- Toast notification --
function showToast(message, duration = 3000) {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.classList.add("show");

    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => {
        toast.classList.remove("show");
    }, duration);

}

// --- Copy password helper for windows ---
async function copyPasswordNoHistory(text) {
    // Try windows no-history copy first
    try {
        await window.__TAURI__.core.invoke("copy_to_clipboard_no_history", { text });
        return;
    } catch (e) {
        // If not on windows, fall back
        // console.debug("no-history copy unavailable, using standard copy:", e);
    }
    await window.__TAURI__.core.invoke("copy_to_clipboard", { text });
}

// --- Copy password ---
async function copyPassword(id) {
    try {
        const value = await invoke("vault_get", { id });
        try {
            // await invoke("copy_to_clipboard", { text: value }); // old way
            await copyPasswordNoHistory(value);
            showToast("Copied");
            console.log("copy to clipboard successful");
        } catch (e) {
            console.error('Failed to copy:', e);
            return;
        }
        // 
        const myToken = ++clipboardOwnerToken;

        // cancel any old timers for existing copy action
        if (clipboardClearTimer) {
            clearTimeout(clipboardClearTimer);
            clipboardClearTimer = null;
        }
        // start countdown for latest copy
        clipboardClearTimer = setTimeout(async() => {
            // verify still latest copy 
            if (myToken !== clipboardOwnerToken) return;

            try {
                const current_clipboard = await invoke("get_clipboard_text");
                if (current_clipboard === value) {
                    // await invoke("copy_to_clipboard", { text: "" }); // old way
                    await copyPasswordNoHistory("");
                    showToast("Clipboard cleared");
                }
            } catch (err) {
                console.log("Clipboard read/clear error:", err);
            } finally {
                if (myToken === clipboardOwnerToken) {
                    clipboardClearTimer = null;
                }
            }
        }, PASS_VIS_DURATION);
    } catch (err) {
        console.log("Copy failed:", err);
    }
}

// --- Delete an entry ---
async function deleteEntry(id, row, label) {
    const ok = await ask(`Delete entry: "${label}"?`, {
        title: "Tauri",
        kind: "warning",
    });
    if (!ok) return;

    try {
        await invoke("vault_delete", { id });
        row.remove();
        console.log("JS done with deleteEntry: ", id)
    } catch (err) {
        console.log("Delete failed:", err);
    }
}

// --- Make entry row ---
function renderRow(e) {
    const tpl = document.getElementById('entry-row-tpl');
    const row = tpl.content.firstElementChild.cloneNode(true);

    row.dataset.id = e.id;

    row.querySelector('.entry-label').textContent = e.label;
    row.querySelector('.entry-username').textContent = e.username;
    row.querySelector('.entry-notes').textContent = (e.notes == null ? '' : e.notes);

    const secretSpan = row.querySelector('.secret');
    secretSpan.textContent = BULLETS;
    const showBtn = row.querySelector('.show');
    showBtn.addEventListener('click', () => showPassword(e.id, secretSpan, showBtn));

    row.querySelector('.copy').addEventListener('click', () => copyPassword(e.id));
    row.querySelector('.delete').addEventListener('click', () => deleteEntry(e.id, row, e.label));

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
    // clear sensitive DOM value immediately
    passwordEl.value = "";
    const notesRaw = notesEl.value;
    const notes = notesRaw.trim().length ? notesRaw : null;

    try {
        await invoke("vault_add", { label, username, password, notes });
        // clear inputs after add
        labelEl.value = "";
        usernameEl.value = "";
        notesEl.value = "";

        // reload list with new entry
        await loadEntries();
    } catch (err) {
        console.log("Error adding entry: ", err);
    } finally {
        // ensure sensitive var is cleared
        password = null;
    }
}


window.addEventListener("DOMContentLoaded", async(e) => {
    e.preventDefault();
    try {
        // 1) Is vault initialized? If not, go create one.
        const s = await invoke("debug_kem_status");
        const initialized = s && (s.sk_exists || s.pk_kem_bytes_len > 0 || s.ct_kem_bytes_len > 0);
        if (!initialized) {
            return window.location.replace("create.html");
        }

        // 2) Is this session unlocked?
        const { loaded } = await invoke("debug_vault_key_status");
        if (!loaded) return window.location.replace("unlock.html");

        // 3) Good to load entries
        await loadEntries();
    } catch (err) {
        console.error("Init check failed:", err);
        // If anything goes sideways, send to unlock to be safe.
        window.location.replace("unlock.html");
    }
});