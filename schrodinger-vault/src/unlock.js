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
const resetBtn = document.querySelector("#reset-btn");

resetBtn.style.display = "none";
resetBtn.addEventListener("click", async () => {

  resetBtn.disabled = true;
  resetBtn.textContent = "Resetting...";

  try {
    await invoke("factory_reset_vault");

    resetBtn.style.display = "none";
    resetBtn.disabled = false;
    unlockBtn.disabled = false;
    window.location.replace("create.html");
  } catch (err) {
    msg.textContent = "Reset failed. Restart required.";
  }

});


// Handle the unlock form submit
form.addEventListener("submit", async (e) => {
  e.preventDefault();          // stop normal form refreshs
  msg.textContent = "";        // clear any previous message

  const pw = document.querySelector("#password").value; // get typed password

  try {

    const now = Date.now();
    msg.textContent = "";  
    if (now < lockUntil) {
        msg.textContent =`Too many attempts. Try again in ${(lockUntil - now) / 1000}s.`;
        return;
    }


    // try unlocking the vault
    await invoke("unlock_vault", { password: pw });

    // redirect to entries page if no failures
    failedAttempts = 0;
    lockUntil = 0;
    window.location.replace("index.html");
  } catch (err) {
    console.error("Unlock failed:", err);

    const msgText =
      typeof err === "string"
        ? err
        : (err?.message || "");

    // 1. tampered vault (manifest corrupted)
    if (msgText.includes("modified outside")) {
        msg.textContent =
            "This vault has been modified outside of Schrödinger Vault. Unlock blocked.";
        unlockBtn.disabled = true; 
        resetBtn.style.display = "block";
        return;
    }

    // 2. device key missing ot ct_kem corrupted 
    if (msgText.includes("device key") || msgText.includes("vault data corrupted")) {
        msg.textContent =
            "Vault cannot be unlocked — device key missing or vault data corrupted.";
        unlockBtn.disabled = true;
        resetBtn.style.display = "block";
        return;
    }

 
    // 3. wrong password. user can try again after a delay
    failedAttempts++;

    const delay = Math.min(BASE_DELAY * (2 ** (failedAttempts - 1)), MAX_DELAY);
    lockUntil = Date.now() + delay;

    const baseMsg =
      typeof err === "string" && err.trim()
        ? err
        : (err?.message || "That password didn’t work.");

    msg.textContent = `${baseMsg} (wait ${Math.round(delay / 1000)}s)`;

    // Disable unlock button during the wait
    unlockBtn.disabled = true;
    setTimeout(() => {
        unlockBtn.disabled = false;
    }, delay);

    //
    // 4. --- Hard lockout after N failures ---
    //
    if (failedAttempts >= MAX_FAILS) {
        msg.textContent =
            "Too many failed attempts — restart the app to try again.";
        unlockBtn.disabled = true;
    }
  }
});
