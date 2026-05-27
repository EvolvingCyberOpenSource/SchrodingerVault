// bridges to call Rust commands from JavaScript
const { invoke } = window.__TAURI__.core;
const { ask } = window.__TAURI__.dialog;

const PASS_VIS_DURATION = 10000; // Time till password is hidden (10s)
const BULLETS = "••••••••";

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

// --- Copy password ---
async function copyPassword(id) {
    let value = null;
    try {
        value = await invoke("vault_get", { id });
        await invoke("copy_secret_to_clipboard", {
            text: value,
            clearAfterMs: PASS_VIS_DURATION,
        });
        showToast("Copied");
    } catch (err) {
        console.log("Copy failed:", err);
    } finally {
        value = null;
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

function setupEditEntryDialog() {
    const dialog = document.getElementById("edit-entry-dialog");
    const form = document.getElementById("edit-entry-form");
    const cancelBtn = document.getElementById("cancel-edit-entry");
    const submitBtn = document.getElementById("submit-edit-entry");
    const labelInput = document.getElementById("edit-entry-label");
    const usernameInput = document.getElementById("edit-entry-username");
    const passwordInput = document.getElementById("edit-entry-password");
    const notesInput = document.getElementById("edit-entry-notes");
    const msg = document.getElementById("edit-entry-msg");

    if (!dialog || !form) return;

    const clearForm = () => {
        form.reset();
        form.dataset.entryId = "";
        msg.textContent = "";
        passwordInput.value = "";
    };

    cancelBtn.addEventListener("click", () => {
        clearForm();
        dialog.close();
    });

    dialog.addEventListener("close", () => {
        passwordInput.value = "";
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        msg.textContent = "";

        const id = Number(form.dataset.entryId);
        const label = labelInput.value;
        const username = usernameInput.value;
        let password = passwordInput.value;
        const notesRaw = notesInput.value;
        const notes = notesRaw.trim().length ? notesRaw : null;

        if (!id) {
            msg.textContent = "No entry selected.";
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Saving...";
        try {
            await invoke("vault_update", { id, label, username, password, notes });
            clearForm();
            dialog.close();
            await loadEntries();
            showToast("Entry updated");
        } catch (err) {
            console.error("Entry update failed:", err);
            msg.textContent = String(err);
        } finally {
            password = null;
            submitBtn.disabled = false;
            submitBtn.textContent = "Save";
        }
    });
}

async function openEditEntry(entry) {
    const dialog = document.getElementById("edit-entry-dialog");
    const form = document.getElementById("edit-entry-form");
    const labelInput = document.getElementById("edit-entry-label");
    const usernameInput = document.getElementById("edit-entry-username");
    const passwordInput = document.getElementById("edit-entry-password");
    const notesInput = document.getElementById("edit-entry-notes");
    const msg = document.getElementById("edit-entry-msg");

    if (!dialog || !form) return;

    msg.textContent = "";
    form.dataset.entryId = String(entry.id);
    labelInput.value = entry.label;
    usernameInput.value = entry.username;
    notesInput.value = entry.notes || "";
    passwordInput.value = "";
    dialog.showModal();
    labelInput.focus();

    try {
        passwordInput.value = await invoke("vault_get", { id: entry.id });
    } catch (err) {
        console.error("Loading entry password failed:", err);
        msg.textContent = String(err);
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

async function refreshKeyDerivationStatus() {
    const label = document.getElementById("current-kdf-label");
    const button = document.getElementById("change-kdf-btn");
    if (!label) return;

    try {
        const status = await invoke("key_derivation_status");
        label.textContent = status.label;
        label.dataset.kdf = status.kdf;
        if (button) button.disabled = false;
    } catch (err) {
        console.error("Key derivation status failed:", err);
        label.textContent = "Unavailable";
        if (button) button.disabled = true;
    }
}

function setupKeyDerivationDialog() {
    const openBtn = document.getElementById("change-kdf-btn");
    const dialog = document.getElementById("change-kdf-dialog");
    const form = document.getElementById("change-kdf-form");
    const cancelBtn = document.getElementById("cancel-change-kdf");
    const submitBtn = document.getElementById("submit-change-kdf");
    const passwordEl = document.getElementById("kdf-master-password");
    const msg = document.getElementById("change-kdf-msg");
    const currentLabel = document.getElementById("current-kdf-label");

    if (!openBtn || !dialog || !form) return;

    passwordEl.addEventListener("keydown", (event) => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        form.requestSubmit();
    });

    const clearForm = () => {
        form.reset();
        msg.textContent = "";
        const currentKdf = currentLabel?.dataset.kdf ?? "argon2id";
        const currentRadio = form.querySelector(`input[name="settings-kdf"][value="${currentKdf}"]`);
        if (currentRadio) currentRadio.checked = true;
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

        const currentPassword = passwordEl.value;
        const kdf = form.querySelector('input[name="settings-kdf"]:checked')?.value;
        if (!currentPassword) {
            msg.textContent = "Enter the current master password.";
            return;
        }
        if (!kdf) {
            msg.textContent = "Choose a key derivation mode.";
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Updating...";
        try {
            await invoke("change_key_derivation_mode", { currentPassword, kdf });
            clearForm();
            dialog.close();
            await refreshKeyDerivationStatus();
            showToast("Key derivation mode updated");
        } catch (err) {
            console.error("Key derivation mode change failed:", err);
            msg.textContent = String(err);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Update Mode";
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
    row.querySelector('.edit').addEventListener('click', () => openEditEntry(e));
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
    setupEditEntryDialog();
    setupKeyDerivationDialog();
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

        await refreshKeyDerivationStatus();
        await loadEntries();
    } catch (err) {
        console.error("Init check failed:", err);
        // If anything goes sideways, send to unlock to be safe.
        window.location.replace("unlock.html");
    }
});
