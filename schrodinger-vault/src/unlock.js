const { invoke } = window.__TAURI__.core;

document.querySelector("#unlock-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const password = document.querySelector("#password").value;
    console.log(password);

    await invoke("unlock_vault", { password: password });

});