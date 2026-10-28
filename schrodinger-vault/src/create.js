const { invoke } = window.__TAURI__.core;
const createMessage = document.querySelector("#create-msg");
const passwordForm = document.querySelector("#passwordForm");
let creatingVault = false;

function submitOnEnter(input, form) {
  input.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    form.requestSubmit();
  });
}

/**
 * Validates the password and confirm password fields.
 *
 * @returns {boolean} true if pasword meets requirements, false otherwise
 */
function validatePassword(password, confirmPassword) {
  if (password !== confirmPassword) {
    createMessage.textContent = "Passwords do not match!";
    return false;
  }

  if (password.length < 10) {
    createMessage.textContent = "Password length is too short! (10 characters minimum)";
    return false;
  }

  // can add more validation here if needed
  return true;
}

/**
 * Anonymous function to handle the create password form submission.
 * Will validate the password then hash with a salt and store in the database.
 * A vault table for entries will also be created in the database.
 *
 * @returns {void}
 */
submitOnEnter(document.querySelector("#masterPassword"), passwordForm);
submitOnEnter(document.querySelector("#confirmPassword"), passwordForm);

passwordForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (creatingVault) return;

  let password = document.querySelector("#masterPassword").value;
  let confirm_Password = document.querySelector("#confirmPassword").value;
  const kdf = document.querySelector('input[name="kdf"]:checked')?.value ?? "argon2id";

  if (!validatePassword(password, confirm_Password)) return;
  creatingVault = true;
  const submitButton = passwordForm.querySelector('button[type="submit"]');
  if (submitButton) submitButton.disabled = true;
  document.querySelector("#masterPassword").value = "";
  document.querySelector("#confirmPassword").value = "";

  try {
    await invoke("create_vault", { masterPassword: password, kdf });
    window.location.replace("index.html");
  } catch (e) {
    console.error(e);
    createMessage.textContent = `Failed to create vault: ${String(e)}`;
  } finally {
    password = "";
    confirm_Password = "";
    creatingVault = false;
    if (submitButton) submitButton.disabled = false;
  }
});
