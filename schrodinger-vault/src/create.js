const { invoke } = window.__TAURI__.core;
const createMessage = document.querySelector("#create-msg");


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
document.querySelector("#passwordForm").addEventListener("submit", async (e) => {
    e.preventDefault();

    const password = document.querySelector("#masterPassword").value;
    const confirmPassword = document.querySelector("#confirmPassword").value;

    // validate password
    // const validated = validatePassword(password, confirmPassword);
    // if (!validated) {
    //   return;
    // }

    //TODO: hash password with salt and store in database
    // We still have t

    console.log("password entered: ", password)
    await invoke("create_vault", { masterPassword: password });
    window.location.replace('index.html');
});