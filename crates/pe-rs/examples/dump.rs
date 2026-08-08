//! The standalone **pe dump tool**: dump a process (typically a paused one),
//! scan its IAT against the process's loaded modules with a chosen method, fix
//! the imports and write the rebuilt file. It knows nothing about the target —
//! point it at any pid, like Scylla's "Fix Dump".
//!
//! ```
//! cargo run -p pe-rs --example dump -- <pid> [out] [--method resolver|reflection|code] [--no-validate]
//! ```
//!
//! `--method` picks the scan line (docs/dump 情况分析和处理.md): `resolver`
//! (default) for a normal import directory, `reflection` for a loader-overwritten
//! OFT / cleared import directory, `code` for an erased + split IAT. `code`
//! validates each referenced slot's content through the resolver by default;
//! pass `--no-validate` for protected dumps whose slots do not resolve.

use pe_rs::api::{IatFixer, IatScanner, PeViewer};
use pe_rs::domain::{IatFixOptions, ScanMethod, ScanOptions};
use pe_rs::io::pe::serialize;
use pe_rs::process;

fn main() {
    let mut args = std::env::args().skip(1);
    let pid = args
        .next()
        .map(|s| s.parse::<u32>().expect("pid must be a u32"))
        .unwrap_or_else(std::process::id);
    let mut out: Option<String> = None;
    let mut method = ScanMethod::Resolver;
    let mut validate = true;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--method" => {
                method = match args.next().as_deref() {
                    Some("resolver") => ScanMethod::Resolver,
                    Some("reflection") => ScanMethod::Reflection,
                    Some("code") => ScanMethod::CodeReference,
                    Some(other) => {
                        eprintln!("unknown method '{other}' (resolver|reflection|code)");
                        std::process::exit(2);
                    }
                    None => {
                        eprintln!("--method needs a value");
                        std::process::exit(2);
                    }
                };
            }
            "--no-validate" => validate = false,
            other if out.is_none() => out = Some(other.to_string()),
            other => {
                eprintln!("unexpected argument '{other}'");
                std::process::exit(2);
            }
        }
    }
    if let Err(e) = run(pid, out.as_deref(), method, validate) {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn run(
    pid: u32,
    out: Option<&str>,
    method: ScanMethod,
    validate: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut doc = process::dump(pid)?;
    println!(
        "dumped pid {pid}: arch={:?} sections={} imports={}",
        doc.arch(),
        doc.sections().len(),
        doc.imports().len(),
    );

    let resolver = process::ProcessResolver::for_process(pid)?;
    println!("resolver: {} loaded modules", resolver.module_names().len());

    let scan = doc.scan(
        &resolver,
        &ScanOptions {
            method,
            validate_slots: validate,
            ..Default::default()
        },
    )?;
    println!(
        "scan ({method:?}, validate_slots={validate}): {} IAT entries at {:#x}",
        scan.entries.len(),
        scan.base_rva.get(),
    );

    let report = doc.fix_iat(&scan, &resolver, &IatFixOptions::default())?;
    println!(
        "fixed: {} imports built, {} unresolved, in-place={}",
        report.imports_built,
        report.unresolved.len(),
        report.iat_reused,
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
