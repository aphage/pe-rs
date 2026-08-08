//! Forces the MSVC linker to use our no-CRT entry point (`mainCRTStartup`)
//! instead of the standard library's.

fn main() {
    // Only the bin target of this crate is no_std / no_main.
    println!("cargo:rustc-link-arg-bins=/ENTRY:mainCRTStartup");
    println!("cargo:rustc-link-arg-bins=/NODEFAULTLIB");
}
