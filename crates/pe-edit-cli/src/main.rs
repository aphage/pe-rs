//! `pe-edit` — CLI for the `pe-edit` library: view and edit **disk** PE files
//! (the CFF-Explorer benchmark). The PE image is parsed from a file, edited in
//! memory, and serialized back to disk.
//!
//! ```
//! pe-edit show C:\Windows\System32\kernel32.dll
//! pe-edit set-entry app.exe 0x14000 out.exe
//! pe-edit add-section app.exe .mydata 4096 out.exe
//! pe-edit add-import app.exe kernel32.dll GetTickCount out.exe
//! pe-edit merge-sections app.exe 1 2 out.exe
//! pe-edit rebuild-sections app.exe out.exe
//! ```

use pe_edit::api::{ImportTableEditor, PeEditor, PeViewer};
use pe_edit::domain::section::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use pe_edit::domain::{DataDirectoryIndex, ResourceEntryData, Rva};
use pe_edit::feature::{merge_sections, rebuild_section_table};
use pe_edit::io::pe::{parse, serialize};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: pe-edit <command> [...]");
        eprintln!(
            "commands: show, set-entry, add-section, add-import, merge-sections, rebuild-sections"
        );
        std::process::exit(2);
    }
    let result = match args[0].as_str() {
        "show" => cmd_show(args.get(1).map(String::as_str)),
        "set-entry" => cmd_set_entry(&args),
        "add-section" => cmd_add_section(&args),
        "add-import" => cmd_add_import(&args),
        "merge-sections" => cmd_merge_sections(&args),
        "rebuild-sections" => cmd_rebuild_sections(&args),
        other => {
            eprintln!("unknown command '{other}'");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

/// Load `path`, apply `edit`, serialize and write to `out`.
fn edit_save(
    path: &str,
    out: &str,
    edit: impl FnOnce(
        &mut pe_edit::domain::PeDocument,
    ) -> Result<(), Box<dyn std::error::Error + 'static>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let mut doc = parse(&bytes)?;
    edit(&mut doc)?;
    let out_bytes = serialize(&doc)?;
    std::fs::write(out, &out_bytes)?;
    println!("wrote {} bytes to {out}", out_bytes.len());
    Ok(())
}

fn arg<'a>(
    args: &'a [String],
    i: usize,
    what: &str,
) -> Result<&'a str, Box<dyn std::error::Error + 'static>> {
    args.get(i)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {what}").into())
}

fn cmd_show(path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Err("usage: pe-edit show <file>".into());
    };
    let bytes = std::fs::read(path)?;
    println!("=== {path} ({}) ===", bytes.len());
    let doc = parse(&bytes)?;
    print_document(&doc);
    run_checks(&doc)
}

fn cmd_set_entry(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = arg(args, 1, "<file>")?;
    let rva = arg(args, 2, "<rva>")?;
    let out = arg(args, 3, "<out>")?;
    let rva = parse_rva(rva)?;
    edit_save(path, out, |doc| {
        doc.optional.set_address_of_entry_point(Rva(rva));
        Ok(())
    })
}

fn cmd_add_section(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = arg(args, 1, "<file>")?;
    let name = arg(args, 2, "<name>")?;
    let size = arg(args, 3, "<size>")?;
    let out = arg(args, 4, "<out>")?;
    let size: usize = size.parse().map_err(|_| "size must be an integer")?;
    edit_save(path, out, |doc| {
        let mut name_bytes = [0u8; 8];
        let n = name.len().min(8);
        name_bytes[..n].copy_from_slice(&name.as_bytes()[..n]);
        let chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        doc.add_section(name_bytes, chars, vec![0; size])?;
        Ok(())
    })
}

fn cmd_add_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = arg(args, 1, "<file>")?;
    let module = arg(args, 2, "<module>")?;
    let func = arg(args, 3, "<func>")?;
    let out = arg(args, 4, "<out>")?;
    edit_save(path, out, |doc| {
        doc.add_import(module, &[pe_edit::domain::ImportFunction::by_name(func)])?;
        Ok(())
    })
}

fn cmd_merge_sections(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = arg(args, 1, "<file>")?;
    let start = arg(args, 2, "<start>")?;
    let end = arg(args, 3, "<end>")?;
    let out = arg(args, 4, "<out>")?;
    let start: usize = start.parse().map_err(|_| "start must be an integer")?;
    let end: usize = end.parse().map_err(|_| "end must be an integer")?;
    edit_save(path, out, move |doc| {
        merge_sections(doc, start, end)?;
        Ok(())
    })
}

fn cmd_rebuild_sections(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = arg(args, 1, "<file>")?;
    let out = arg(args, 2, "<out>")?;
    edit_save(path, out, |doc| {
        rebuild_section_table(doc)?;
        Ok(())
    })
}

/// Parse a base like `0x14000` or `81920` (decimal).
fn parse_rva(s: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    }
    .map_err(|_| format!("invalid rva '{s}'").into())
}

fn print_document(doc: &pe_edit::domain::PeDocument) {
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

fn count_resource_leaves(dir: &pe_edit::domain::ResourceDirectory) -> usize {
    dir.entries.iter().fold(0, |acc, e| match &e.data {
        ResourceEntryData::Directory(d) => acc + count_resource_leaves(d),
        ResourceEntryData::Leaf(_) => acc + 1,
    })
}

fn run_checks(doc: &pe_edit::domain::PeDocument) -> Result<(), Box<dyn std::error::Error>> {
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

fn import_total(doc: &pe_edit::domain::PeDocument) -> usize {
    doc.imports().iter().map(|d| d.functions.len()).sum()
}
