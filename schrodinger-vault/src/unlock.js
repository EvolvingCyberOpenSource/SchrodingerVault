// Tauri invoke lets JS call Rust commands
const { invoke } = window.__TAURI__.core;

// Grab form and message display elements
const form = document.querySelector("#unlock-form");
const msg  = document.querySelector("#unlock-msg");

// Handle the unlock form submit
form.addEventListener("submit", async (e) => {
  e.preventDefault();          // stop normal form refresh
  msg.textContent = "";        // clear any previous message

  const pw = document.querySelector("#password").value; // get typed password

  try {
    // === Ask Rust to unlock the vault ===
    await invoke("unlock_vault", { password: pw });

    // === Mark session as unlocked ===
    // This tells main.js that this session is unlocked
    // It only lasts until the window/app closes (RAM only)
    
    // TODO STEP 3: Once backend derives VAULT_AES_KEY on unlock,
    // remove this sessionStorage flag. The entries page will gate
    // using Rust `debug_vault_key_status` instead.
    sessionStorage.setItem("vault_unlocked", "1");

    // === Redirect to entries page ===
    window.location.replace("index.html");
  } catch (err) {
    // === Handle errors from Rust ===
    // Examples: missing SK file, corrupted ciphertext, wrong password
    console.error("Unlock failed:", err);

    // Show the message returned from Rust if available, else a friendly default
    msg.textContent =
      typeof err === "string" && err.trim()
        ? err
        : (err?.message || "Failed to unlock. Please try again.");
  }
});
