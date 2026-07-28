#![windows_subsystem = "windows"]

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::{self, BufRead, Write as _};
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, ERROR_NOT_FOUND, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW,
    CredWriteW,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::Win32::System::WinRT::{
    IUserConsentVerifierInterop, RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize,
};
use windows::Win32::UI::Controls::{
    TASKDIALOG_COMMON_BUTTON_FLAGS, TASKDIALOGCONFIG, TDCBF_NO_BUTTON, TDCBF_YES_BUTTON,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_POSITION_RELATIVE_TO_WINDOW, TDF_SIZE_TO_CONTENT,
    TaskDialogIndirect,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, MSG,
    PM_REMOVE, PeekMessageW, RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE,
    WNDCLASSW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows_future::{AsyncStatus, IAsyncOperation};
use zeroize::{Zeroize as _, Zeroizing};

const MAX_MESSAGE_BYTES: u64 = 64 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 2048;
const HELLO_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const CREDENTIAL_TARGET: &str = "io.github.reisuzunami.sloosh/native-approval-v1";
const CREDENTIAL_USER: &str = "vault-master-password";

#[derive(Deserialize)]
struct Request {
    r#type: String,
    master_password: Option<String>,
    hosts: Option<Vec<String>>,
    purpose: Option<String>,
    confirm: Option<bool>,
    host_label: Option<String>,
}

#[derive(Serialize)]
struct Response<'a> {
    r#type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    master_password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pin: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    touch_id_enrolled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pin_credential_stored: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

impl<'a> Response<'a> {
    fn simple(r#type: &'a str) -> Self {
        Self {
            r#type,
            master_password: None,
            ssh_password: None,
            pin: None,
            touch_id_enrolled: None,
            pin_credential_stored: None,
            code: None,
            message: None,
        }
    }

    fn error(code: &'a str, message: &'a str) -> Self {
        Self {
            code: Some(code),
            message: Some(message),
            ..Self::simple("error")
        }
    }
}

fn main() {
    if let Err(message) = trusted_parent() {
        send(&Response::error("untrusted_parent", &message));
        std::process::exit(1);
    }
    let owner = match OwnerWindow::create() {
        Ok(owner) => owner,
        Err(error) => {
            let message = format!("Could not create the Windows Hello owner window: {error}");
            send(&Response::error("unavailable", &message));
            std::process::exit(1);
        }
    };
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let Some(first) = receive(&mut input) else {
        send(&Response::error(
            "invalid_request",
            "Missing or invalid helper request",
        ));
        std::process::exit(1);
    };
    let ok = handle(first, &mut input, owner.hwnd());
    std::process::exit(if ok { 0 } else { 1 });
}

fn handle(first: Request, input: &mut impl BufRead, hwnd: HWND) -> bool {
    match first.r#type.as_str() {
        "status" => {
            let enrolled = credential_exists();
            send(&Response {
                touch_id_enrolled: Some(enrolled),
                pin_credential_stored: Some(false),
                ..Response::simple("approval_status")
            });
            true
        }
        "enroll" => {
            let Some(password) = first.master_password else {
                send(&Response::error(
                    "invalid_request",
                    "Enrollment password is missing",
                ));
                return false;
            };
            let password = Zeroizing::new(password);
            match verify_hello(hwnd, "Enable Windows Hello approval for Sloosh") {
                Ok(()) => match store_credential(&password) {
                    Ok(()) => {
                        send(&Response::simple("enrolled"));
                        true
                    }
                    Err(message) => {
                        send(&Response::error("credential_manager", &message));
                        false
                    }
                },
                Err(error) => send_hello_error(error),
            }
        }
        "unlock_with_touch_id" => match load_credential() {
            Ok(password) => match verify_hello(hwnd, "Unlock Sloosh") {
                Ok(()) => {
                    send(&Response {
                        master_password: Some(&password),
                        ..Response::simple("unlocked")
                    });
                    true
                }
                Err(error) => send_hello_error(error),
            },
            Err(message) => {
                send(&Response::error("not_enrolled", &message));
                false
            }
        },
        "begin" => match load_credential() {
            Ok(password) => {
                send(&Response {
                    master_password: Some(&password),
                    ..Response::simple("unlocked")
                });
                let Some(confirm) = receive(input) else {
                    send(&Response::error(
                        "invalid_request",
                        "Missing host confirmation request",
                    ));
                    return false;
                };
                if confirm.r#type != "confirm" {
                    send(&Response::error(
                        "invalid_request",
                        "Expected host confirmation request",
                    ));
                    return false;
                }
                let Some(hosts) = confirm.hosts else {
                    send(&Response::error(
                        "invalid_request",
                        "Host confirmation scope is missing",
                    ));
                    return false;
                };
                if !confirm_hosts(hwnd, &hosts) {
                    send(&Response::error(
                        "cancelled",
                        "Windows Hello approval was cancelled",
                    ));
                    return false;
                }
                match verify_hello(
                    hwnd,
                    &format!("Approve Sloosh access to {}", hosts.join(", ")),
                ) {
                    Ok(()) => {
                        send(&Response::simple("approved"));
                        true
                    }
                    Err(error) => send_hello_error(error),
                }
            }
            Err(message) => {
                send(&Response::error("not_enrolled", &message));
                false
            }
        },
        "prompt_master_password" => {
            let purpose = first.purpose.as_deref().unwrap_or("Authorize Sloosh");
            let confirm = first.confirm.unwrap_or(false);
            match prompt_secret(hwnd, "Sloosh Master Password", purpose) {
                Ok(password) => {
                    if confirm {
                        let second = match prompt_secret(
                            hwnd,
                            "Confirm Sloosh Master Password",
                            "Enter the same vault Master Password again",
                        ) {
                            Ok(value) => value,
                            Err(error) => return send_prompt_error(error),
                        };
                        if *password != *second {
                            send(&Response::error(
                                "mismatch",
                                "Master Password entries do not match",
                            ));
                            return false;
                        }
                    }
                    send(&Response {
                        master_password: Some(&password),
                        ..Response::simple("master_password_entered")
                    });
                    true
                }
                Err(error) => send_prompt_error(error),
            }
        }
        "prompt_ssh_password" => {
            let label = first.host_label.as_deref().unwrap_or("SSH host");
            match prompt_secret(hwnd, "SSH Password", &format!("Password for {label}")) {
                Ok(password) => {
                    send(&Response {
                        ssh_password: Some(&password),
                        ..Response::simple("ssh_password_entered")
                    });
                    true
                }
                Err(error) => send_prompt_error(error),
            }
        }
        "remove_pin_credential" => {
            send(&Response::simple("pin_credential_removed"));
            true
        }
        "prompt_pin" | "store_pin_credential" | "begin_pin_unlock" => {
            send(&Response::error(
                "not_enrolled",
                "Windows uses the Windows Hello PIN fallback; a separate Sloosh PIN is not available",
            ));
            false
        }
        _ => {
            send(&Response::error(
                "invalid_request",
                "Unsupported helper request",
            ));
            false
        }
    }
}

enum HelloError {
    Cancelled,
    Unavailable(String),
}

fn verify_hello(hwnd: HWND, message: &str) -> Result<(), HelloError> {
    // The helper's main thread owns `hwnd` and must keep dispatching messages.
    // Run the potentially blocking WinRT call in an MTA worker so Windows can
    // synchronously message the owner without deadlocking this thread.
    let hwnd_value = hwnd.0 as usize;
    let message = message.to_owned();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("sloosh-windows-hello".into())
        .spawn(move || {
            let hwnd = HWND(hwnd_value as *mut std::ffi::c_void);
            let result = verify_hello_worker(hwnd, &message);
            let _ = sender.send(result);
        })
        .map_err(|error| {
            HelloError::Unavailable(format!("Could not start Windows Hello: {error}"))
        })?;

    let started = Instant::now();
    loop {
        match receiver.try_recv() {
            Ok(result) => return result,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(HelloError::Unavailable(
                    "Windows Hello worker stopped unexpectedly".to_string(),
                ));
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        pump_window_messages();
        if started.elapsed() >= HELLO_TIMEOUT {
            return Err(HelloError::Unavailable(
                "Windows Hello timed out".to_string(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn verify_hello_worker(hwnd: HWND, message: &str) -> Result<(), HelloError> {
    // SAFETY: this dedicated worker initializes and uninitializes its own WinRT
    // apartment; no WinRT interface escapes the worker.
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(|error| {
        HelloError::Unavailable(format!("Could not initialize Windows Runtime: {error}"))
    })?;
    let _apartment = WinRtApartment;
    let interop: IUserConsentVerifierInterop =
        windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|error| HelloError::Unavailable(error.to_string()))?;
    // SAFETY: `hwnd` is owned by OwnerWindow and remains live until helper exit.
    let operation: IAsyncOperation<UserConsentVerificationResult> =
        unsafe { interop.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(message)) }
            .map_err(|error| HelloError::Unavailable(error.to_string()))?;
    loop {
        let status = operation
            .Status()
            .map_err(|error| HelloError::Unavailable(error.to_string()))?;
        match status {
            AsyncStatus::Completed => break,
            AsyncStatus::Canceled => return Err(HelloError::Cancelled),
            AsyncStatus::Error => {
                return Err(HelloError::Unavailable(
                    operation
                        .ErrorCode()
                        .map(|code| code.to_string())
                        .unwrap_or_else(|error| error.to_string()),
                ));
            }
            _ => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    match operation
        .GetResults()
        .map_err(|error| HelloError::Unavailable(error.to_string()))?
    {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::Canceled => Err(HelloError::Cancelled),
        other => Err(HelloError::Unavailable(format!(
            "Windows Hello verification failed: {other:?}"
        ))),
    }
}

struct WinRtApartment;

impl Drop for WinRtApartment {
    fn drop(&mut self) {
        // SAFETY: paired with the successful RoInitialize call on this worker.
        unsafe { RoUninitialize() };
    }
}

fn pump_window_messages() {
    let mut message = MSG::default();
    // SAFETY: message points to writable storage and every removed message is
    // translated and dispatched on the thread that owns the helper HWND.
    unsafe {
        while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

fn send_hello_error(error: HelloError) -> bool {
    match error {
        HelloError::Cancelled => send(&Response::error("cancelled", "Windows Hello was cancelled")),
        HelloError::Unavailable(message) => send(&Response::error("unavailable", &message)),
    }
    false
}

fn confirm_hosts(hwnd: HWND, hosts: &[String]) -> bool {
    if hosts.is_empty() || hosts.len() > 9 {
        return false;
    }
    let content = hosts
        .iter()
        .map(|host| format!("• {host}"))
        .collect::<Vec<_>>()
        .join("\r\n");
    let title = wide("Approve SSH access?");
    let instruction = wide("Sloosh will grant this request access to:");
    let content = wide(&content);
    let config = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: hwnd,
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION
            | TDF_POSITION_RELATIVE_TO_WINDOW
            | TDF_SIZE_TO_CONTENT,
        dwCommonButtons: TASKDIALOG_COMMON_BUTTON_FLAGS(TDCBF_YES_BUTTON.0 | TDCBF_NO_BUTTON.0),
        pszWindowTitle: PCWSTR(title.as_ptr()),
        pszMainInstruction: PCWSTR(instruction.as_ptr()),
        pszContent: PCWSTR(content.as_ptr()),
        ..Default::default()
    };
    let mut button = 0_i32;
    // SAFETY: all text buffers and output pointers live for the call.
    unsafe { TaskDialogIndirect(&config, Some(&mut button), None, None) }.is_ok() && button == 6
}

struct OwnerWindow(HWND);

impl OwnerWindow {
    fn create() -> windows::core::Result<Self> {
        let class = wide("SlooshApprovalOwnerWindow");
        let title = wide("Sloosh Approval");
        // SAFETY: querying the current module handle with a null module name.
        let instance = unsafe { windows::Win32::System::LibraryLoader::GetModuleHandleW(None) }?;
        let window_class = WNDCLASSW {
            lpfnWndProc: Some(owner_window_proc),
            hInstance: instance.into(),
            lpszClassName: PCWSTR(class.as_ptr()),
            ..Default::default()
        };
        // SAFETY: the class descriptor and UTF-16 strings remain live during calls.
        unsafe { RegisterClassW(&window_class) };
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PCWSTR(class.as_ptr()),
                PCWSTR(title.as_ptr()),
                WINDOW_STYLE::default(),
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                1,
                1,
                None,
                None,
                Some(instance.into()),
                None,
            )
        }?;
        Ok(Self(hwnd))
    }

    fn hwnd(&self) -> HWND {
        self.0
    }
}

unsafe extern "system" fn owner_window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: forwards the parameters supplied by Windows unchanged.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

impl Drop for OwnerWindow {
    fn drop(&mut self) {
        // SAFETY: this helper owns the HWND and destroys it exactly once.
        let _ = unsafe { DestroyWindow(self.0) };
    }
}

fn store_credential(password: &str) -> Result<(), String> {
    if password.is_empty() || password.len() > MAX_CREDENTIAL_BYTES {
        return Err("Master Password is empty or too long for Windows Credential Manager".into());
    }
    let target = wide(CREDENTIAL_TARGET);
    let user = wide(CREDENTIAL_USER);
    let mut blob = Zeroizing::new(password.as_bytes().to_vec());
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_ptr().cast_mut()),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: PWSTR(user.as_ptr().cast_mut()),
        ..Default::default()
    };
    // SAFETY: all credential pointers remain valid for the synchronous call.
    unsafe { CredWriteW(&credential, 0) }.map_err(|error| error.to_string())
}

fn load_credential() -> Result<Zeroizing<String>, String> {
    let target = wide(CREDENTIAL_TARGET);
    let mut raw = ptr::null_mut();
    // SAFETY: `raw` is an output pointer freed with CredFree below.
    unsafe { CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None, &mut raw) }
        .map_err(|_| "Windows Hello approval is not enrolled".to_string())?;
    if raw.is_null() {
        return Err("Windows Credential Manager returned an empty credential".into());
    }
    // SAFETY: CredReadW returned a valid CREDENTIALW allocation.
    let credential = unsafe { &*raw };
    let size = credential.CredentialBlobSize as usize;
    let result = if size == 0 || size > MAX_CREDENTIAL_BYTES {
        Err("Stored Sloosh credential has an invalid size".to_string())
    } else {
        // SAFETY: CredReadW returns writable storage valid for CredentialBlobSize
        // bytes until CredFree. Clear the OS-owned copy before releasing it.
        let bytes = unsafe { std::slice::from_raw_parts_mut(credential.CredentialBlob, size) };
        let decoded = std::str::from_utf8(bytes)
            .map(|value| Zeroizing::new(value.to_owned()))
            .map_err(|_| "Stored Sloosh credential is not valid UTF-8".to_string());
        bytes.zeroize();
        decoded
    };
    // SAFETY: raw was allocated by CredReadW.
    unsafe { CredFree(raw.cast()) };
    result
}

fn credential_exists() -> bool {
    load_credential().is_ok()
}

#[allow(dead_code)]
fn remove_credential() -> Result<(), String> {
    let target = wide(CREDENTIAL_TARGET);
    // SAFETY: target is a live NUL-terminated string.
    match unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None) } {
        Ok(()) => Ok(()),
        Err(error) if error.code().0 as u32 == ERROR_NOT_FOUND.0 => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

enum PromptError {
    Cancelled,
    Failed(String),
}

fn prompt_secret(
    hwnd: HWND,
    caption: &str,
    message: &str,
) -> Result<Zeroizing<String>, PromptError> {
    use windows::Win32::Security::Credentials::{
        CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST, CREDUI_FLAGS_GENERIC_CREDENTIALS,
        CREDUI_FLAGS_KEEP_USERNAME, CREDUI_INFOW, CredUIPromptForCredentialsW,
    };
    let caption = wide(caption);
    let message = wide(message);
    let target = wide(CREDENTIAL_TARGET);
    let mut username = wide("Sloosh");
    username.resize(514, 0);
    let mut password = Zeroizing::new(vec![0_u16; 514]);
    let info = CREDUI_INFOW {
        cbSize: size_of::<CREDUI_INFOW>() as u32,
        hwndParent: hwnd,
        pszMessageText: PCWSTR(message.as_ptr()),
        pszCaptionText: PCWSTR(caption.as_ptr()),
        ..Default::default()
    };
    let flags = CREDUI_FLAGS_ALWAYS_SHOW_UI
        | CREDUI_FLAGS_DO_NOT_PERSIST
        | CREDUI_FLAGS_GENERIC_CREDENTIALS
        | CREDUI_FLAGS_KEEP_USERNAME;
    // SAFETY: all buffers match their advertised character capacities.
    let status = unsafe {
        CredUIPromptForCredentialsW(
            Some(&info),
            PCWSTR(target.as_ptr()),
            None,
            0,
            &mut username,
            &mut password,
            None,
            flags,
        )
    };
    if status == ERROR_CANCELLED {
        return Err(PromptError::Cancelled);
    }
    if status.0 != 0 {
        return Err(PromptError::Failed(format!(
            "Windows credential prompt failed: {status:?}"
        )));
    }
    let end = password
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(password.len());
    let value = String::from_utf16(&password[..end])
        .map_err(|_| PromptError::Failed("Credential prompt returned invalid UTF-16".into()))?;
    password.zeroize();
    if value.is_empty() {
        return Err(PromptError::Failed("Password cannot be empty".into()));
    }
    Ok(Zeroizing::new(value))
}

fn send_prompt_error(error: PromptError) -> bool {
    match error {
        PromptError::Cancelled => send(&Response::error(
            "cancelled",
            "Password input was cancelled",
        )),
        PromptError::Failed(message) => send(&Response::error("invalid_input", &message)),
    }
    false
}

fn trusted_parent() -> Result<(), String> {
    let helper = std::env::current_exe().map_err(|error| error.to_string())?;
    let helper_dir = helper.parent().ok_or("Helper has no parent directory")?;
    // SAFETY: GetCurrentProcessId has no preconditions.
    let current_pid = unsafe { GetCurrentProcessId() };
    let parent_pid = parent_pid(current_pid).ok_or("Could not determine helper parent")?;
    let parent = process_path(parent_pid).ok_or("Could not resolve helper parent executable")?;
    for allowed in ["slooshd.exe", "sloosh-desktop.exe"] {
        let expected = helper_dir.join(allowed);
        if paths_equal(&parent, &expected) {
            return Ok(());
        }
    }
    Err(format!(
        "Native approval helper was launched by untrusted process {}",
        parent.display()
    ))
}

fn parent_pid(pid: u32) -> Option<u32> {
    // SAFETY: snapshot is closed before return; dwSize is initialized.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut result = None;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    result = Some(entry.th32ParentProcessID);
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        result
    }
}

fn process_path(pid: u32) -> Option<PathBuf> {
    // SAFETY: handle is closed and buffer matches the supplied size.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        );
        let _ = CloseHandle(process);
        result.ok()?;
        buffer.truncate(length as usize);
        Some(PathBuf::from(OsString::from_wide(&buffer)))
    }
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    let left = left.as_os_str().to_string_lossy();
    let right = right.as_os_str().to_string_lossy();
    left.trim_start_matches(r"\\?\")
        .eq_ignore_ascii_case(right.trim_start_matches(r"\\?\"))
}

fn receive(input: &mut impl BufRead) -> Option<Request> {
    let mut line = String::new();
    let read = std::io::Read::take(input, MAX_MESSAGE_BYTES + 1)
        .read_line(&mut line)
        .ok()?;
    if read == 0 || read as u64 > MAX_MESSAGE_BYTES || !line.ends_with('\n') {
        return None;
    }
    serde_json::from_str(&line).ok()
}

fn send(response: &Response<'_>) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, response).is_ok() {
        let _ = output.write_all(b"\n");
        let _ = output.flush();
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_request_reader_is_bounded_and_requires_newline() {
        let mut valid = io::Cursor::new(b"{\"type\":\"status\"}\n".to_vec());
        assert_eq!(receive(&mut valid).unwrap().r#type, "status");

        let mut no_newline = io::Cursor::new(b"{\"type\":\"status\"}".to_vec());
        assert!(receive(&mut no_newline).is_none());

        let mut oversized = io::Cursor::new(vec![b'x'; MAX_MESSAGE_BYTES as usize + 1]);
        assert!(receive(&mut oversized).is_none());
    }

    #[test]
    fn parent_path_comparison_normalizes_windows_prefix_and_case() {
        assert!(paths_equal(
            Path::new(r"C:\Sloosh\sloosh-desktop.exe"),
            Path::new(r"\\?\c:\sloosh\SLOOSH-DESKTOP.EXE")
        ));
    }
}
