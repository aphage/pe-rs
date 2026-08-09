//! Contract tests for [`pe_edit::api::PeViewer`], run against both the mock
//! document and the same content through the real parser (round-trip).

mod common;

use pe_edit::api::PeViewer;
use pe_edit::domain::{Arch, DataDirectoryIndex, Machine, Rva};
use pe_edit::io::{MOCK_APIS_BASE, MOCK_IAT_RVA, MOCK_IMAGE_BASE, MOCK_TEXT_RVA};

#[test]
fn arch_and_machine_are_x64() {
    common::both(|doc| {
        assert_eq!(doc.arch(), Arch::Bit64);
        assert_eq!(doc.coff_header().machine, Machine::Amd64);
    });
}

#[test]
fn dos_header_has_mz() {
    common::both(|doc| {
        assert!(doc.dos_header().is_mz());
        assert_eq!(doc.dos_header().e_lfanew, 0x40);
    });
}

#[test]
fn optional_header_is_pe32_plus() {
    common::both(|doc| {
        assert_eq!(doc.optional_header().image_base(), MOCK_IMAGE_BASE);
        assert_eq!(
            doc.optional_header().address_of_entry_point().get(),
            MOCK_TEXT_RVA
        );
    });
}

#[test]
fn sections_include_text_and_idata() {
    common::both(|doc| {
        let names: Vec<String> = doc.sections().iter().map(|s| s.name_str()).collect();
        assert!(names.contains(&".text".to_string()));
        assert!(names.contains(&".idata".to_string()));
    });
}

#[test]
fn import_and_iat_directories_present() {
    common::both(|doc| {
        let import = doc.data_directory(DataDirectoryIndex::Import).unwrap();
        assert_ne!(import.rva, Rva::NULL);
        let iat = doc.data_directory(DataDirectoryIndex::Iat).unwrap();
        assert_ne!(iat.rva, Rva::NULL);
    });
}

#[test]
fn imports_match_canonical_table() {
    common::both(|doc| {
        let imports = doc.imports();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].name, "kernel32.dll");
        assert_eq!(imports[0].functions.len(), 5);
        assert!(imports.iter().any(|d| d.name == "user32.dll"));
        assert!(
            imports[0]
                .functions
                .iter()
                .any(|f| f.name() == Some("GetProcAddress"))
        );
    });
}

#[test]
fn exports_are_parsed() {
    common::both(|doc| {
        let exports = doc.exports().expect("mock has exports");
        assert_eq!(exports.symbols.len(), 2);
        assert_eq!(exports.symbols[0].name.as_deref(), Some("Start"));
    });
}

#[test]
fn rva_to_raw_roundtrips() {
    common::both(|doc| {
        let raw = doc.rva_to_raw(Rva(MOCK_TEXT_RVA)).unwrap();
        assert_eq!(doc.raw_to_rva(raw).unwrap(), Rva(MOCK_TEXT_RVA));
    });
}

#[test]
fn read_first_iat_slot() {
    common::both(|doc| {
        let entry = doc.read(Rva(MOCK_IAT_RVA), 8).unwrap();
        let val = u64::from_le_bytes(entry.try_into().unwrap());
        assert_eq!(val, MOCK_APIS_BASE);
    });
}

#[test]
fn read_unmapped_rva_errors() {
    common::both(|doc| {
        assert!(doc.read(Rva(0x9000), 8).is_err());
        assert!(doc.rva_to_raw(Rva(0x9000)).is_err());
    });
}
