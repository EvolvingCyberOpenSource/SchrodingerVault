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

  // check if a user even exists
  // if not, redirect to create password/vault page
  const exists = await userExists();
  if (!exists){
    // window.location.replace("create.html");
  } 
});
