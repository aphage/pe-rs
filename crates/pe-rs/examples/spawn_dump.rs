//! Create a process with the debug flag and dump it **paused at its entry
//! point** — the clean "fully loaded, nothing has run yet" state (relocations
//! and imports applied, `.data`/`.bss` initialized, no runtime-written
//! pointers). This is the correct moment to dump a program. Then scan, fix and
//! save, like `dump.rs` but with the target spawned-and-paused by us.
//!
//! ```
//! cargo run -p pe-rs --example spawn_dump -- <exe> <out> [--method resolver|reflection|code] [--rebase [<base>]] [-- <target args...>]
//! ```

use pe_rs::api::{IatFixer, IatScanner, PeViewer};
use pe_rs::domain::{IatFixOptions, ScanMethod, ScanOptions};
use pe_rs::feature::rebase_dump;
use pe_rs::io::pe::serialize;
use pe_rs::process;

const DEFAULT_PREFERRED_BASE: u64 = 0x1_4000_0000;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut exe: Option<String> = None;
    let mut out: Option<String> = None;
    let mut target_args: Vec<String> = Vec::new();
    let mut method = ScanMethod::Resolver;
    let mut validate = true;
    let mut rebase: Option<u64> = None;
    let mut dump_only = false;
    let mut after_dashdash = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if after_dashdash {
            target_args.push(a.clone());
        } else {
            match a.as_str() {
                "--" => after_dashdash = true,
                "--dump-only" => dump_only = true,
                "--method" => {
                    i += 1;
                    method = match args.get(i).map(|s| s.as_str()) {
                        Some("resolver") => ScanMethod::Resolver,
                        Some("reflection") => ScanMethod::Reflection,
                        Some("code") => ScanMethod::CodeReference,
                        Some(o) => {
                            eprintln!("unknown method '{o}'");
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
                    rebase = match args.get(i + 1).and_then(|v| parse_base(v)) {
                        Some(base) => {
                            i += 1;
                            Some(base)
                        }
                        None => Some(DEFAULT_PREFERRED_BASE),
                    };
                }
                other if exe.is_none() => exe = Some(other.to_string()),
                other if out.is_none() => out = Some(other.to_string()),
                other => {
                    eprintln!("unexpected argument '{other}'");
                    std::process::exit(2);
                }
            }
        }
        i += 1;
    }
    let (Some(exe), Some(out)) = (exe, out) else {
        eprintln!("usage: spawn_dump <exe> <out> [--method ...] [--rebase] [-- args...]");
        std::process::exit(2);
    };
    if let Err(e) = run(
        &exe,
        &target_args,
        &out,
        method,
        validate,
        rebase,
        dump_only,
    ) {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn parse_base(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn run(
    exe: &str,
    target_args: &[String],
    out: &str,
    method: ScanMethod,
    validate: bool,
    rebase: Option<u64>,
    dump_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create the process paused at its entry point; Drop terminates it when we
    // are done dumping.
    let paused = process::spawn_paused(exe, target_args)?;
    let pid = paused.pid;

    let mut doc = process::dump(pid)?;
    // The entry-point byte was temporarily an INT 3 (breakpoint); put the real
    // byte back so the fixed dump has intact code.
    paused.restore_entry_byte(&mut doc)?;
    println!(
        "dumped pid {pid} at its entry point: arch={:?} sections={} imports={}",
        doc.arch(),
        doc.sections().len(),
        doc.imports().len(),
    );

    if dump_only {
        let bytes = serialize(&doc)?;
        std::fs::write(out, &bytes)?;
        println!("wrote {} bytes to {out} (dump only)", bytes.len());
        return Ok(());
    }

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
        "scan ({method:?}, validate_slots={validate}): {} IAT entries",
        scan.entries.len(),
    );

    let report = doc.fix_iat(&scan, &resolver, &IatFixOptions::default())?;
    println!(
        "fixed: {} imports built, {} unresolved, in-place={}",
        report.imports_built,
        report.unresolved.len(),
        report.iat_reused,
    );

    let bytes = serialize(&doc)?;
    std::fs::write(out, &bytes)?;
    println!("wrote {} bytes to {out}", bytes.len());
    Ok(())
}
