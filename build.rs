fn main() {
    // build.rs is compiled/run for the *host*, not the target. Use the
    // target cfg env var so cross-compiles to Windows still link correctly.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=dbghelp");
        println!("cargo:rustc-link-lib=advapi32");
    }
}
