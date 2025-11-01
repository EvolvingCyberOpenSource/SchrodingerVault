// Tauri invoke lets JS call Rust commands
const { invoke } = window.__TAURI__.core;

let failedAttempts = 0;
let lockUntil = 0;
const BASE_DELAY = 2000;  
const MAX_DELAY = 60000;  
const MAX_FAILS = 5;    

// Grab form and message display elements
const form = document.querySelector("#unlock-form");
const msg  = document.querySelector("#unlock-msg");
const unlockBtn = document.querySelector("#unlock-btn");


// Handle the unlock form submit
form.addEventListener("submit", async (e) => {
  e.preventDefault();          // stop normal form refresh
  msg.textContent = "";        // clear any previous message

  const pw = document.querySelector("#password").value; // get typed password

  try {

    const now = Date.now();
    msg.textContent = "";  
    if (now < lockUntil) {
        msg.textContent =`Too many attempts. Try again in ${(lockUntil - now) / 1000}s.`;
        return;
    }


    // === Ask Rust to unlock the vault ===
    await invoke("unlock_vault", { password: pw });

    // === Redirect to entries page ===
    failedAttempts = 0;
    lockUntil = 0;
    window.location.replace("index.html");
  } catch (err) {
    console.error("Unlock failed:", err);

    const msgText = typeof err === "string" ? err : err?.message || "";
    if (msgText.includes("device key") || msgText.includes("vault data corrupted")) {
      msg.textContent = "Vault cannot be unlocked — device key missing or vault data corrupted.";
      unlockBtn.disabled = true;  // no point retrying password is correct but vault broken
      return;
  }
    // Increment failure count
    failedAttempts++;

    // Compute backoff delay 
    const delay = Math.min(BASE_DELAY * (2 ** (failedAttempts - 1)), MAX_DELAY);
    lockUntil = Date.now() + delay;

    // Show user facing message
    const baseMsg =
      typeof err === "string" && err.trim()
        ? err
        : (err?.message || "That password didn’t work.");

    msg.textContent = `${baseMsg} (wait ${Math.round(delay / 1000)}s)`;

    // Disable unlock button during the delay
    unlockBtn.disabled = true;
    setTimeout(() => {
        unlockBtn.disabled = false;
    }, delay);

    // lockout after too many fails
    if (failedAttempts >= MAX_FAILS) {
        msg.textContent = "Too many failed attempts — restart the app to try again.";
        unlockBtn.disabled = true;
        console.log("Vault locked due to excessive failures.");
    }
  }
});
