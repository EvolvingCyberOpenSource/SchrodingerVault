use tauri::command;
use secrecy::{SecretString, ExposeSecret};
use arboard::Clipboard;

#[cfg(target_os = "windows")]
use windows::{
    core::w,
    Win32::{
        Foundation::{HANDLE, HGLOBAL},
        System::{
            DataExchange::{
                CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW,
                SetClipboardData,
            },
            Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT},
        },
    },
};

#[cfg(target_os = "windows")]
const CF_UNICODETEXT: u32 = 13;

// For Windows: places text on clipboard without storing in clipboard history.
#[tauri::command]
#[cfg(target_os = "windows")]
pub fn copy_to_clipboard_no_history(text: &str) -> Result<(), String> {
    unsafe {
        OpenClipboard(None).map_err(|e| format!("OpenClipboard failed: {e}"))?;
        struct Close;
        impl Drop for Close {
            fn drop(&mut self) { unsafe { let _ = CloseClipboard(); } }
        }
        let _guard = Close;
        EmptyClipboard().map_err(|e| format!("EmptyClipboard failed: {e}"))?;
        let mut utf16: Vec<u16> = text.encode_utf16().collect();
        utf16.push(0);
        let byte_len = utf16.len() * 2;
        let h_text: HGLOBAL = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, byte_len)
            .map_err(|e| format!("GlobalAlloc(text) failed: {e}"))?;
        let p = GlobalLock(h_text);
        if p.is_null() { return Err("GlobalLock(text) failed".into()); }
        std::ptr::copy_nonoverlapping(utf16.as_ptr() as *const u8, p as *mut u8, byte_len);
        GlobalUnlock(h_text);
        if let Err(e) = SetClipboardData(CF_UNICODETEXT, HANDLE(h_text.0)) {
            return Err(format!("SetClipboardData(CF_UNICODETEXT) failed: {e}"));
        }
        let fmt_exclude = RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing"));
        if fmt_exclude == 0 { return Err("RegisterClipboardFormatW(exclude) failed".into()); }
        let h_flag: HGLOBAL = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4)
            .map_err(|e| format!("GlobalAlloc(flag) failed: {e}"))?;
        if let Err(e) = SetClipboardData(fmt_exclude, HANDLE(h_flag.0)) {
            return Err(format!("SetClipboardData(exclude) failed: {e}"));
        }
        Ok(())
    }
}

#[command]
pub fn copy_to_clipboard(text: String) -> Result<(), String> {
    let secret = SecretString::from(text);
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(secret.expose_secret()).map_err(|e| e.to_string())?;
    Ok(())
}

#[command]
pub fn get_clipboard_text() -> Result<String, String> {
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    let text = SecretString::from(clipboard.get_text().map_err(|e| e.to_string())?);
    Ok(text.expose_secret().to_string())
}
