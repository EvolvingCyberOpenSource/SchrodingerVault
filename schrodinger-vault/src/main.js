// bridges to call Rust commands from JavaScript
const { invoke } = window.__TAURI__.core;
const { ask } = window.__TAURI__.dialog;

const PASS_VIS_DURATION = 10000; // Time till password is hidden (10s)
const BULLETS = "••••••••";

// single clipboard timer and owner token
let clipboardClearTimer = null;
let clipboardOwnerToken = 0;

// Idle timeout auto-lock timer
const IDLE_TIMEOUT = 5 * 60 * 1000; // 5 mins
let idleTimer = null;

function resetIdleTimer() {
    if (idleTimer) clearTimeout(idleTimer);

    idleTimer = setTimeout(() => {
        console.log("User idle for 5 minutes. Auto-locking...");
        lockVault();
    }, IDLE_TIMEOUT);
}

// Register activity events to reset timer
function registerIdleListeners() {
    const events = ["mousemove", "keydown", "click", "scroll", "touchstart"];
    events.forEach(ev => {
        document.addEventListener(ev, resetIdleTimer, { passive: true });
    });
}

// --- Password reveal ---
function hidePassword(secretSpan, showBtn) {
    if (showBtn._hideTimer) {
        clearTimeout(showBtn._hideTimer);
        showBtn._hideTimer = null;
    }
    secretSpan.textContent = BULLETS;
    secretSpan.classList.remove("revealed");
    showBtn.dataset.visible = "false";
    showBtn.setAttribute("aria-label", "Show password");
    showBtn.title = "Show password";
    showBtn.disabled = false;
}

async function togglePassword(id, secretSpan, showBtn, errorMsg) {
    errorMsg.textContent = "";
    if (showBtn.dataset.visible === "true") {
        hidePassword(secretSpan, showBtn);
        return;
    }

    try {
        showBtn.disabled = true;
        const value = await invoke("vault_get", { id });
        secretSpan.textContent = value;
        secretSpan.classList.add("revealed");
        showBtn.dataset.visible = "true";
        showBtn.setAttribute("aria-label", "Hide password");
        showBtn.title = "Hide password";
        showBtn.disabled = false;
        showBtn._hideTimer = setTimeout(() => {
            hidePassword(secretSpan, showBtn);
        }, PASS_VIS_DURATION);
    } catch (err) {
        console.log("Show failed:", err);
        errorMsg.textContent = err;
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

// --- Lock Vault ---
async function lockVault() {
    try {
        // Call the Rust command
        await invoke("lock_vault");

        // Redirect to unlock page
        window.location.replace("unlock.html");
    } catch (err) {
        console.error("Error locking vault:", err);
        showToast("Failed to lock vault");
    }
}

function setupChangePasswordDialog() {
    const openBtn = document.getElementById("change-password-btn");
    const dialog = document.getElementById("change-password-dialog");
    const form = document.getElementById("change-password-form");
    const cancelBtn = document.getElementById("cancel-change-password");
    const submitBtn = document.getElementById("submit-change-password");
    const currentEl = document.getElementById("current-master-password");
    const newEl = document.getElementById("new-master-password");
    const confirmEl = document.getElementById("confirm-master-password");
    const msg = document.getElementById("change-password-msg");

    if (!openBtn || !dialog || !form) return;

    [currentEl, newEl, confirmEl].forEach((input) => {
        input.addEventListener("keydown", (event) => {
            if (event.key !== "Enter") return;
            event.preventDefault();
            form.requestSubmit();
        });
    });

    const clearForm = () => {
        form.reset();
        msg.textContent = "";
    };

    openBtn.addEventListener("click", () => {
        clearForm();
        dialog.showModal();
        currentEl.focus();
    });

    cancelBtn.addEventListener("click", () => {
        clearForm();
        dialog.close();
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        msg.textContent = "";

        const currentPassword = currentEl.value;
        const newPassword = newEl.value;
        const confirmPassword = confirmEl.value;

        if (newPassword.length < 10) {
            msg.textContent = "Use at least 10 characters.";
            return;
        }
        if (newPassword !== confirmPassword) {
            msg.textContent = "New passwords do not match.";
            return;
        }
        if (currentPassword === newPassword) {
            msg.textContent = "Choose a different new password.";
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Updating...";
        try {
            await invoke("change_master_password", { currentPassword, newPassword });
            clearForm();
            dialog.close();
            showToast("Master password updated");
        } catch (err) {
            console.error("Password change failed:", err);
            msg.textContent = String(err);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Update";
        }
    });
}

function setupFactoryResetDialog() {
    const openBtn = document.getElementById("factory-reset-btn");
    const dialog = document.getElementById("factory-reset-dialog");
    const form = document.getElementById("factory-reset-form");
    const cancelBtn = document.getElementById("cancel-factory-reset");
    const submitBtn = document.getElementById("submit-factory-reset");
    const passwordEl = document.getElementById("reset-master-password");
    const msg = document.getElementById("factory-reset-msg");

    if (!openBtn || !dialog || !form) return;

    passwordEl.addEventListener("keydown", (event) => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        form.requestSubmit();
    });

    const clearForm = () => {
        form.reset();
        msg.textContent = "";
    };

    openBtn.addEventListener("click", () => {
        clearForm();
        dialog.showModal();
        passwordEl.focus();
    });

    cancelBtn.addEventListener("click", () => {
        clearForm();
        dialog.close();
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        msg.textContent = "";

        const masterPassword = passwordEl.value;
        if (!masterPassword) {
            msg.textContent = "Enter the master password to reset.";
            return;
        }

        const ok = await ask("This will permanently delete the vault. Continue?", {
            title: "Factory Reset",
            kind: "warning",
        });
        if (!ok) return;

        submitBtn.disabled = true;
        submitBtn.textContent = "Resetting...";
        try {
            await invoke("factory_reset_vault", { masterPassword });
            clearForm();
            dialog.close();
            showToast("Vault reset");
            window.location.replace("create.html");
        } catch (err) {
            console.error("Factory reset failed:", err);
            msg.textContent = String(err);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Reset Vault";
        }
    });
}

function setupTabs() {
    const tabButtons = document.querySelectorAll("[data-tab-target]");
    const panels = document.querySelectorAll(".tab-panel");

    tabButtons.forEach((button) => {
        button.addEventListener("click", () => {
            const targetId = button.dataset.tabTarget;
            tabButtons.forEach((btn) => btn.classList.toggle("active", btn === button));
            panels.forEach((panel) => panel.classList.toggle("active", panel.id === targetId));
        });
    });
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
    const errorMsg = row.querySelector('.errorMsg');
    secretSpan.textContent = BULLETS;
    const showBtn = row.querySelector('.show');
    showBtn.dataset.visible = "false";
    showBtn.addEventListener('click', () => togglePassword(e.id, secretSpan, showBtn, errorMsg));

    row.querySelector('.copy').addEventListener('click', () => copyPassword(e.id));
    row.querySelector('.delete').addEventListener('click', () => deleteEntry(e.id, row, e.label));

    return row;
}

// --- Load all entries into html list ---
let entryCache = [];

function entryMatchesSearch(entry, query) {
    if (!query) return true;
    const haystack = [
        entry.label,
        entry.username,
        entry.notes || "",
    ].join(" ").toLowerCase();
    return haystack.includes(query);
}

function renderEntries(items) {
    const container = document.getElementById("entry-list");
    container.innerHTML = "";

    if (!items || items.length === 0) {
        container.textContent = entryCache.length ? "No matching entries." : "No entries yet.";
        return;
    }

    for (const e of items) {
        container.appendChild(renderRow(e));
    }
}

function applyEntrySearch() {
    const searchEl = document.getElementById("entry-search");
    const query = (searchEl?.value || "").trim().toLowerCase();
    renderEntries(entryCache.filter((entry) => entryMatchesSearch(entry, query)));
}

async function loadEntries() {
    try {
        entryCache = await invoke("vault_list");
        applyEntrySearch();
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
    let password = passwordEl.value;
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
    const lockBtn = document.getElementById("lock-vault-btn");
    if (lockBtn) {
        lockBtn.addEventListener("click", lockVault);
    }
    setupChangePasswordDialog();
    setupFactoryResetDialog();
    setupTabs();
    const searchEl = document.getElementById("entry-search");
    if (searchEl) {
        searchEl.addEventListener("input", applyEntrySearch);
    }

    // start idle auto-locking
    registerIdleListeners();
    resetIdleTimer();

    try {
        const initialized = await invoke("vault_exists");
        if (!initialized) {
            return window.location.replace("create.html");
        }

        const { loaded } = await invoke("vault_session_status");
        if (!loaded) return window.location.replace("unlock.html");

        await loadEntries();
    } catch (err) {
        console.error("Init check failed:", err);
        // If anything goes sideways, send to unlock to be safe.
        window.location.replace("unlock.html");
    }
});
