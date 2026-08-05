//! Dump a live process, scan its IAT against the process's loaded modules, fix
//! the imports, and (optionally) write the rebuilt file.
//!
//! ```
//! cargo run -p pe-rs --example dump -- [pid] [out.bin]   # default pid: this process
//! ```

use pe_rs::api::{IatFixer, IatScanner, PeViewer};
use pe_rs::domain::{IatFixOptions, ScanOptions};
use pe_rs::io::pe::serialize;
use pe_rs::process;

fn main() {
    let mut args = std::env::args().skip(1);
    let pid = args
        .next()
        .map(|s| s.parse::<u32>().expect("pid must be a u32"))
        .unwrap_or_else(std::process::id);
    let out = args.next();
    if let Err(e) = run(pid, out.as_deref()) {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn run(pid: u32, out: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let mut doc = process::dump(pid)?;
    println!(
        "dumped pid {pid}: arch={:?} sections={} imports={}",
        doc.arch(),
        doc.sections().len(),
        doc.imports().len(),
    );

    let resolver = process::ProcessResolver::for_process(pid)?;
    println!("resolver: {} loaded modules", resolver.module_names().len());

    let scan = doc.scan(&resolver, &ScanOptions::default())?;
    println!(
        "IAT at {:#x}, {} entries",
        scan.base_rva.get(),
        scan.entries.len()
    );

    let report = doc.fix_iat(&scan, &resolver, &IatFixOptions::default())?;
    println!(
        "fixed: {} imports built, {} unresolved, new table at {:#x}",
        report.imports_built,
        report.unresolved.len(),
        report.new_import_rva.map(|r| r.get()).unwrap_or(0),
    );

    let bytes = serialize(&doc)?;
    let re = pe_rs::io::pe::parse(&bytes)?;
    println!("round-trip: {} imports preserved", re.imports.len());

    if let Some(path) = out {
        std::fs::write(path, &bytes)?;
        println!("wrote {} bytes to {path}", bytes.len());
    }
    Ok(())
}
