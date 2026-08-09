//! Round-trip tests for saving/loading the import tree (JSON + XML).

use pe_edit::domain::ImportFunction;
use pe_edit::io::{MOCK_IAT_RVA, mock};
use pe_scylla::api::{ImportEntry, ImportModule, ImportStatus, ImportsTree};
use pe_scylla::io::tree::{TreeFile, load_json, load_xml, save_json, save_xml};
use std::path::PathBuf;

fn sample_tree() -> ImportsTree {
    let modules: Vec<ImportModule> = mock::mock_imports()
        .into_iter()
        .map(|d| {
            let mut rva = MOCK_IAT_RVA;
            let entries: Vec<ImportEntry> = d
                .functions
                .into_iter()
                .map(|f| {
                    let e = ImportEntry {
                        slot_va: 0,
                        slot_rva: rva,
                        api_address: 0,
                        function: Some(f),
                        module: d.name.clone(),
                        status: ImportStatus::Valid,
                    };
                    rva += 8;
                    e
                })
                .collect();
            ImportModule {
                name: d.name,
                first_thunk: MOCK_IAT_RVA as u64,
                entries,
            }
        })
        .collect();
    ImportsTree { modules }
}

fn file() -> TreeFile {
    TreeFile {
        oep: 0x1234,
        iat_va: 0x140008000,
        iat_size: 0x80,
        tree: sample_tree(),
    }
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    dir.join(format!("pe_rs_tree_{}_{name}", std::process::id()))
}

#[test]
fn json_round_trip() {
    let path = tmp("t.json");
    save_json(&path, &file()).expect("save json");
    let loaded = load_json(&path).expect("load json");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded.oep, 0x1234);
    assert_eq!(loaded.iat_va, 0x140008000);
    assert_eq!(loaded.iat_size, 0x80);
    assert_eq!(loaded.tree.total(), 6);
    assert_eq!(loaded.tree.modules.len(), 2);
    let k32 = &loaded.tree.modules[0];
    assert_eq!(k32.name, "kernel32.dll");
    assert_eq!(k32.entries.len(), 5);
    assert!(matches!(
        k32.entries[0].function,
        Some(ImportFunction::Name { .. })
    ));
    assert_eq!(k32.entries[0].status, ImportStatus::Valid);
}

#[test]
fn xml_round_trip() {
    let path = tmp("t.xml");
    save_xml(&path, &file()).expect("save xml");
    let loaded = load_xml(&path).expect("load xml");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded.oep, 0x1234);
    assert_eq!(loaded.iat_va, 0x140008000);
    assert_eq!(loaded.tree.total(), 6);
    assert_eq!(loaded.tree.modules[0].name, "kernel32.dll");
    assert_eq!(loaded.tree.modules[0].entries.len(), 5);
}
