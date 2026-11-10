fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if target_os == "windows" || (target_os.is_empty() && cfg!(windows)) {
        // The first choice is Windows because DXGI is amazing.
        println!("cargo:rustc-cfg=dxgi");
    } else if target_os == "macos" || (target_os.is_empty() && cfg!(target_os = "macos")) {
        // Quartz is second because macOS is the (annoying) exception.
        println!("cargo:rustc-cfg=quartz");
    } else if target_family == "unix" || (target_family.is_empty() && cfg!(unix)) {
        // On UNIX we pray that X11 (with XCB) is available.
        println!("cargo:rustc-cfg=x11");
    }
}
