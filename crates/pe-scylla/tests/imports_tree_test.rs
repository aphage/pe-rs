//! Tests for the Get Imports / Fix Dump tree: the `ImportsTree` model and
//! rebuilding a document from a curated tree (`fix_iat_from_tree`). The mock
//! document's contiguous IAT (kernel32 ×5 + user32 ×1 at `MOCK_IAT_RVA`) is
//! reproduced as a tree, fixed, and the rebuilt imports compared.

use pe_edit::domain::IatFixOptions;
use pe_edit::io::pe::serialize;
use pe_edit::io::{MOCK_IAT_RVA, MockSource};
use pe_scylla::api::{ImportEntry, ImportModule, ImportStatus, ImportsTree, fix_iat_from_tree};

/// The mock document's import table (kernel32 ×5, user32 ×1).
fn mock_modules() -> Vec<(String, Vec<pe_edit::domain::ImportFunction>)> {
    pe_edit::io::mock::mock_imports()
        .into_iter()
        .map(|d| (d.name, d.functions))
        .collect()
}

/// Build the tree matching the mock document's contiguous IAT: every entry is
/// valid and slot-contiguous within its module.
fn tree_from_mock() -> ImportsTree {
    let mut modules = Vec::new();
    let mut rva = MOCK_IAT_RVA;
    for (name, functions) in mock_modules() {
        let first = rva;
        let entries: Vec<ImportEntry> = functions
            .into_iter()
            .map(|f| ImportEntry {
                slot_va: 0,
                slot_rva: rva,
                api_address: 0,
                function: Some(f),
                module: name.clone(),
                status: ImportStatus::Valid,
            })
            .collect();
        rva += entries.len() as u32 * 8;
        modules.push(ImportModule {
            name,
            first_thunk: first as u64,
            entries,
        });
    }
    ImportsTree { modules }
}

#[test]
fn fix_iat_from_tree_rebuilds_mock_imports() {
    let mut doc = MockSource::document();
    let tree = tree_from_mock();

    assert_eq!(tree.total(), 6);
    assert_eq!(tree.valid(), 6);
    assert_eq!(tree.invalid(), 0);
    assert_eq!(tree.suspect(), 0);

    let report =
        fix_iat_from_tree(&mut doc, &tree, &IatFixOptions::default(), None).expect("fix from tree");
    assert_eq!(report.imports_built, 2);
    assert_eq!(report.unresolved.len(), 0);

    // The rebuilt import table matches the mock's canonical imports.
    let expected = pe_edit::io::mock::mock_imports();
    assert_eq!(doc.imports, expected);

    // And survives a serialize → re-parse round-trip.
    let bytes = serialize(&doc).expect("serialize");
    let re = pe_edit::io::pe::parse(&bytes).expect("re-parse");
    assert_eq!(re.imports, expected);
}

#[test]
fn fix_iat_from_tree_drops_invalid_entries_and_writes_oep() {
    let mut doc = MockSource::document();
    let mut tree = tree_from_mock();

    // Mark one kernel32 entry invalid and add an "<unknown>" module.
    let k32 = tree
        .modules
        .iter_mut()
        .find(|m| m.name == "kernel32.dll")
        .unwrap();
    k32.entries[2].status = ImportStatus::Invalid;
    tree.modules.push(ImportModule {
        name: "<unknown>".into(),
        first_thunk: 0,
        entries: vec![ImportEntry {
            slot_va: 0,
            slot_rva: 0x9000,
            api_address: 0x7777_0000,
            function: None,
            module: String::new(),
            status: ImportStatus::Invalid,
        }],
    });

    let report = fix_iat_from_tree(&mut doc, &tree, &IatFixOptions::default(), Some(0x1234))
        .expect("fix from tree");
    // 5 kernel32 entries kept (one dropped), 1 user32 → 2 modules.
    assert_eq!(report.imports_built, 2);
    assert_eq!(
        doc.imports.iter().map(|d| d.functions.len()).sum::<usize>(),
        5
    );
    // OEP was written.
    assert_eq!(doc.optional.address_of_entry_point().get(), 0x1234);
}
