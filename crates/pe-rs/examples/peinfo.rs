//! Parse a real PE file, print its structure, and run consistency checks
//! (including a full serialize → re-parse round-trip).
//!
//! ```
//! cargo run -p pe-rs --example peinfo -- C:\Windows\System32\kernel32.dll
//! ```

use pe_rs::api::PeViewer;
use pe_rs::domain::{DataDirectoryIndex, ResourceEntryData, Rva};
use pe_rs::io::pe::{parse, serialize};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: peinfo <path-to-pe>");
        std::process::exit(2);
    };
    if let Err(e) = run(&path) {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn run(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    println!("=== {path} ({}) ===", bytes.len());
    let doc = parse(&bytes)?;
    print_document(&doc);
    run_checks(&doc)
}

fn print_document(doc: &pe_rs::domain::PeDocument) {
    println!(
        "arch: {:?}, machine: {:?}",
        doc.arch(),
        doc.coff_header().machine
    );
    println!(
        "image_base: {:#x}, entry: {:#x}, subsystem: {}",
        doc.optional_header().image_base(),
        doc.optional_header().address_of_entry_point().get(),
        doc.optional_header().subsystem(),
    );

    println!("sections ({}):", doc.sections().len());
    for s in doc.sections() {
        println!(
            "  {:<10} va={:#8x} vsize={:#8x} raw={:#8x} @{:#8x} char={:#8x}",
            s.name_str(),
            s.header.virtual_address.get(),
            s.header.virtual_size,
            s.header.size_of_raw_data,
            s.header.pointer_to_raw_data.get(),
            s.header.characteristics,
        );
    }

    let import_count: usize = doc.imports().iter().map(|d| d.functions.len()).sum();
    println!(
        "imports: {} modules, {} functions",
        doc.imports().len(),
        import_count
    );
    for d in doc.imports() {
        let named = d.functions.iter().filter(|f| f.name().is_some()).count();
        println!(
            "  {:<28} {:4} funcs ({} named)",
            d.name,
            d.functions.len(),
            named
        );
    }

    match doc.exports() {
        Some(exports) => {
            let sample: Vec<String> = exports
                .symbols
                .iter()
                .take(4)
                .map(|s| {
                    format!(
                        "{}(#{})={:#x}",
                        s.name.as_deref().unwrap_or("<ordinal>"),
                        s.ordinal,
                        s.rva.get()
                    )
                })
                .collect();
            println!(
                "exports: {} symbols (module {:?})  e.g. {}",
                exports.symbols.len(),
                exports.module_name,
                sample.join(", ")
            );
        }
        None => println!("exports: none"),
    }

    if let Some(res) = doc.resources() {
        println!(
            "resources: {} top entries, {} leaves",
            res.entries.len(),
            count_resource_leaves(res)
        );
    } else {
        println!("resources: none");
    }

    match doc.relocations() {
        Some(reloc) => {
            let entries: usize = reloc.blocks.iter().map(|b| b.entries.len()).sum();
            println!(
                "relocations: {} blocks, {} entries",
                reloc.blocks.len(),
                entries
            );
        }
        None => println!("relocations: none"),
    }

    match doc.tls() {
        Some(t) => println!(
            "tls: start={:#x} end={:#x} callbacks={:#x}",
            t.start_address_of_raw_data, t.end_address_of_raw_data, t.address_of_callbacks
        ),
        None => println!("tls: none"),
    }

    match doc.load_config() {
        Some(lc) => println!(
            "load_config: size={:#x} cookie={:#x} cf_flags={:#x} cf_table={:#x} ({} funcs) xfg_check={:#x}",
            lc.size,
            lc.security_cookie,
            lc.guard_flags,
            lc.guard_cf_function_table,
            lc.guard_cf_function_count,
            lc.guard_xfg_check_function_pointer,
        ),
        None => println!("load_config: none"),
    }
}

fn count_resource_leaves(dir: &pe_rs::domain::ResourceDirectory) -> usize {
    dir.entries.iter().fold(0, |acc, e| match &e.data {
        ResourceEntryData::Directory(d) => acc + count_resource_leaves(d),
        ResourceEntryData::Leaf(_) => acc + 1,
    })
}

fn run_checks(doc: &pe_rs::domain::PeDocument) -> Result<(), Box<dyn std::error::Error>> {
    println!("checks:");

    // Directory RVAs must point into mapped memory (or be null).
    for idx in [
        DataDirectoryIndex::Export,
        DataDirectoryIndex::Import,
        DataDirectoryIndex::Resource,
        DataDirectoryIndex::BaseReloc,
        DataDirectoryIndex::Iat,
        DataDirectoryIndex::Tls,
    ] {
        let Some(dd) = doc
            .data_directory(idx)
            .ok()
            .filter(|dd| dd.rva != Rva::NULL)
        else {
            continue;
        };
        if doc.read(dd.rva, 4).is_err() {
            return Err(format!(
                "{} directory rva {:#x} is unmapped",
                idx.name(),
                dd.rva.get()
            )
            .into());
        }
    }
    println!("  [PASS] data-directory rvas are mapped");

    // serialize → re-parse must preserve imports, exports, section content.
    let bytes = serialize(doc)?;
    let reparsed = parse(&bytes)?;
    let ok_imports = reparsed.imports == doc.imports;
    let ok_exports = reparsed.exports == doc.exports;
    let ok_sections = doc.sections().len() == reparsed.sections().len()
        && doc.sections().iter().all(|s| {
            reparsed
                .sections
                .iter()
                .find(|r| r.name_str() == s.name_str())
                .is_some_and(|r| {
                    r.data == s.data && r.header.virtual_address == s.header.virtual_address
                })
        });
    println!(
        "  [{}] round-trip preserves imports ({} modules / {} funcs)",
        if ok_imports { "PASS" } else { "FAIL" },
        doc.imports().len(),
        import_total(doc)
    );
    println!(
        "  [{}] round-trip preserves exports ({} symbols)",
        if ok_exports { "PASS" } else { "FAIL" },
        doc.exports().map(|e| e.symbols.len()).unwrap_or(0)
    );
    println!(
        "  [{}] round-trip preserves sections ({} total)",
        if ok_sections { "PASS" } else { "FAIL" },
        doc.sections().len()
    );
    if !(ok_imports && ok_exports && ok_sections) {
        return Err("round-trip checks failed".into());
    }
    Ok(())
}

fn import_total(doc: &pe_rs::domain::PeDocument) -> usize {
    doc.imports().iter().map(|d| d.functions.len()).sum()
}
