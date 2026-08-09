//! `pe-scylla` — CLI for the `pe-scylla` library: dump a (typically paused /
//! debugged) process, scan its IAT against the process's loaded modules with a
//! chosen method, fix the imports and write the rebuilt file. It knows nothing
//! about the target — point it at any pid, like Scylla's "Fix Dump".
//!
//! ```
//! pe-scylla <pid> [out] [--method resolver|reflection|code] [--no-validate] [--rebase [<base>]]
//! ```
//!
//! `--method` picks the scan line (docs/dump 情况分析和处理.md): `resolver`
//! (default) for a normal import directory, `reflection` for a loader-overwritten
//! OFT / cleared import directory, `code` for an erased + split IAT. `code`
//! validates each referenced slot's content through the resolver by default;
//! pass `--no-validate` for protected dumps whose slots do not resolve.
//!
//! `--rebase [<base>]` rewrites the dump's base relocation table so it re-runs
//! standalone even when the program's runtime wrote absolute pointers into
//! `.data` (see `pe_scylla::feature::rebase_dump`). `<base>` defaults to
//! `0x140000000`.

use pe_edit::api::PeViewer;
use pe_edit::io::pe::serialize;
use pe_scylla::api::{IatFixer, IatScanner};
use pe_scylla::feature::rebase_dump;
use pe_scylla::process;
use pe_scylla::{IatFixOptions, ScanMethod, ScanOptions};

const DEFAULT_PREFERRED_BASE: u64 = 0x1_4000_0000; // 0x140000000, typical x64 exe base

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pid = args
        .first()
        .map(|s| s.parse::<u32>().expect("pid must be a u32"))
        .unwrap_or_else(std::process::id);
    let mut out: Option<String> = None;
    let mut method = ScanMethod::Resolver;
    let mut validate = true;
    let mut rebase: Option<u64> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--method" => {
                i += 1;
                method = match args.get(i).map(|s| s.as_str()) {
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
            "--rebase" => {
                // Optional base value (default 0x140000000); an arg that isn't
                // a number is the next positional, not a base.
                rebase = match args.get(i + 1).and_then(|v| parse_base(v)) {
                    Some(base) => {
                        i += 1;
                        Some(base)
                    }
                    None => Some(DEFAULT_PREFERRED_BASE),
                };
            }
            other if out.is_none() => out = Some(other.to_string()),
            other => {
                eprintln!("unexpected argument '{other}'");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    if let Err(e) = run(pid, out.as_deref(), method, validate, rebase) {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

/// Parse a base like `0x140000000` or `1400000000` (decimal).
fn parse_base(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn run(
    pid: u32,
    out: Option<&str>,
    method: ScanMethod,
    validate: bool,
    rebase: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut doc = process::dump(pid)?;
    println!(
        "dumped pid {pid}: arch={:?} sections={} imports={}",
        doc.arch(),
        doc.sections().len(),
        doc.imports().len(),
    );

    if let Some(base) = rebase {
        let report = rebase_dump(&mut doc, base)?;
        println!(
            "rebased dump to {base:#x}: {} image pointers, {} runtime slots cleared",
            report.rebased, report.cleared
        );
    }

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
    let re = pe_edit::io::pe::parse(&bytes)?;
    println!("round-trip: {} imports preserved", re.imports.len());

    if let Some(path) = out {
        std::fs::write(path, &bytes)?;
        println!("wrote {} bytes to {path}", bytes.len());
    }
    Ok(())
}
