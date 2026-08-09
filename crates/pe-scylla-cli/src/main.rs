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
use pe_scylla::api::{IatFixer, IatScanner, ImportStatus, fix_iat_from_tree, get_imports};
use pe_scylla::feature::rebase_dump;
use pe_scylla::process;
use pe_scylla::{IatFixOptions, ScanMethod, ScanOptions};

const DEFAULT_PREFERRED_BASE: u64 = 0x1_4000_0000; // 0x140000000, typical x64 exe base

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(cmd) = args.first().map(String::as_str) {
        match cmd {
            "get-imports" => cmd_get_imports(&args[1..]),
            "fix-tree" => cmd_fix_tree(&args[1..]),
            "search-iat" => cmd_search_iat(&args[1..]),
            _ => cmd_dump(&args),
        }
    } else {
        cmd_dump(&args);
    }
}

fn cmd_search_iat(args: &[String]) {
    let pid = args
        .first()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(|| usage("search-iat <pid> [start_va] [--advanced]"));
    let mut start_va: Option<u64> = None;
    let mut advanced = false;
    for a in &args[1..] {
        match a.as_str() {
            "--advanced" => advanced = true,
            other => start_va = parse_u64(other),
        }
    }
    let start_va = match start_va {
        Some(va) => va,
        None => {
            // Default: the target's entry point (runtime base + entry RVA).
            match process::dump(pid) {
                Ok(doc) => {
                    let base = process::module_range(pid)
                        .map(|(b, _)| b)
                        .unwrap_or(doc.optional.image_base());
                    base + doc.optional.address_of_entry_point().get() as u64
                }
                Err(e) => die(&format!("dump failed: {e}")),
            }
        }
    };
    match process::search_iat(pid, start_va, advanced) {
        Ok(Some((va, size))) => {
            let resolver = match process::ProcessResolver::for_process(pid) {
                Ok(r) => r,
                Err(e) => die(&format!("resolver failed: {e}")),
            };
            println!(
                "IAT VA {:#x} RVA {:#x} size 0x{:x} ({})",
                va,
                va.saturating_sub(resolver.image_base),
                size,
                size
            );
        }
        Ok(None) => {
            eprintln!("IAT not found from {:#x}", start_va);
            std::process::exit(1);
        }
        Err(e) => die(&format!("search failed: {e}")),
    }
}

fn cmd_get_imports(args: &[String]) {
    let pid = args
        .first()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(|| usage("get-imports <pid> <iat_va> <iat_size>"));
    let iat_va = args
        .get(1)
        .and_then(|s| parse_u64(s))
        .unwrap_or_else(|| usage("get-imports <pid> <iat_va> <iat_size>"));
    let iat_size = args
        .get(2)
        .and_then(|s| parse_usize(s))
        .unwrap_or_else(|| usage("get-imports <pid> <iat_va> <iat_size>"));
    let resolver = match process::ProcessResolver::for_process(pid) {
        Ok(r) => r,
        Err(e) => die(&format!("resolver failed: {e}")),
    };
    let tree = match get_imports(pid, &resolver, iat_va, iat_size) {
        Ok(t) => t,
        Err(e) => die(&format!("get imports failed: {e}")),
    };
    println!(
        "{} modules, {} imports ({} valid, {} suspect, {} invalid)",
        tree.modules.len(),
        tree.total(),
        tree.valid(),
        tree.suspect(),
        tree.invalid(),
    );
    for m in &tree.modules {
        println!(
            "  {:<28} first_thunk={:#x} ({} entries)",
            m.name,
            m.first_thunk,
            m.entries.len()
        );
        for e in &m.entries {
            let st = match e.status {
                ImportStatus::Valid => "valid  ",
                ImportStatus::Suspect => "suspect",
                ImportStatus::Invalid => "invalid",
            };
            println!("      {st} rva={:#x} {}", e.slot_rva, e.label());
        }
    }
}

fn cmd_fix_tree(args: &[String]) {
    let mut pid: Option<u32> = None;
    let mut out: Option<String> = None;
    let mut iat_va: Option<u64> = None;
    let mut iat_size: Option<usize> = None;
    let mut oep: Option<u32> = None;
    let mut rebase: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--iat-va" => {
                i += 1;
                iat_va = Some(
                    args.get(i)
                        .and_then(|s| parse_u64(s))
                        .unwrap_or_else(|| usage("fix-tree: --iat-va <va>")),
                );
            }
            "--iat-size" => {
                i += 1;
                iat_size = Some(
                    args.get(i)
                        .and_then(|s| parse_usize(s))
                        .unwrap_or_else(|| usage("fix-tree: --iat-size <size>")),
                );
            }
            "--oep" => {
                i += 1;
                oep = Some(
                    args.get(i)
                        .and_then(|s| parse_u64(s))
                        .map(|v| v as u32)
                        .unwrap_or_else(|| usage("fix-tree: --oep <rva>")),
                );
            }
            "--rebase" => {
                rebase = match args.get(i + 1).and_then(|v| parse_u64(v)) {
                    Some(base) => {
                        i += 1;
                        Some(base)
                    }
                    None => Some(DEFAULT_PREFERRED_BASE),
                };
            }
            other if pid.is_none() => pid = other.parse::<u32>().ok(),
            other if out.is_none() => out = Some(other.to_string()),
            other => eprintln!("unexpected argument '{other}'"),
        }
        i += 1;
    }
    let (pid, out, iat_va, iat_size) = (
        pid.unwrap_or_else(|| usage("fix-tree <pid> <out> --iat-va <va> --iat-size <size>")),
        out.unwrap_or_else(|| usage("fix-tree <pid> <out> --iat-va <va> --iat-size <size>")),
        iat_va.unwrap_or_else(|| usage("fix-tree: --iat-va <va>")),
        iat_size.unwrap_or_else(|| usage("fix-tree: --iat-size <size>")),
    );

    let mut doc = match process::dump(pid) {
        Ok(d) => d,
        Err(e) => die(&format!("dump failed: {e}")),
    };
    if let Some(base) = rebase {
        match rebase_dump(&mut doc, base) {
            Ok(r) => println!(
                "rebased dump to {base:#x}: {} image pointers, {} runtime slots cleared",
                r.rebased, r.cleared
            ),
            Err(e) => die(&format!("rebase failed: {e}")),
        }
    }
    let resolver = match process::ProcessResolver::for_process(pid) {
        Ok(r) => r,
        Err(e) => die(&format!("resolver failed: {e}")),
    };
    let tree = match get_imports(pid, &resolver, iat_va, iat_size) {
        Ok(t) => t,
        Err(e) => die(&format!("get imports failed: {e}")),
    };
    println!(
        "get imports: {} modules, {} valid, {} suspect, {} invalid",
        tree.modules.len(),
        tree.valid(),
        tree.suspect(),
        tree.invalid(),
    );
    let report = match fix_iat_from_tree(&mut doc, &tree, &IatFixOptions::default(), oep) {
        Ok(r) => r,
        Err(e) => die(&format!("fix from tree failed: {e}")),
    };
    println!(
        "fixed: {} imports built, {} unresolved, in-place={}",
        report.imports_built,
        report.unresolved.len(),
        report.iat_reused,
    );
    match serialize(&doc) {
        Ok(bytes) => match std::fs::write(&out, &bytes) {
            Ok(()) => println!("wrote {} bytes to {out}", bytes.len()),
            Err(e) => die(&format!("write failed: {e}")),
        },
        Err(e) => die(&format!("serialize failed: {e}")),
    }
}

fn cmd_dump(args: &[String]) {
    let pid = args
        .first()
        .and_then(|s| s.parse::<u32>().ok())
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
    parse_u64(s)
}

/// Parse a `u64` as hex (`0x…`) or decimal.
fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Parse a `usize` as hex (`0x…`) or decimal.
fn parse_usize(s: &str) -> Option<usize> {
    parse_u64(s).map(|v| v as usize)
}

/// Print `msg` and exit 2 (usage error).
fn usage(msg: &str) -> ! {
    eprintln!("usage: {msg}");
    std::process::exit(2);
}

/// Print `msg` and exit 1 (failure).
fn die(msg: &str) -> ! {
    eprintln!("FAILED: {msg}");
    std::process::exit(1);
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
