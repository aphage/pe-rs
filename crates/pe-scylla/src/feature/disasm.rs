//! Disassembly of a document's section (for the GUI's Disassembler view).

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

use pe_edit::domain::{PeDocument, Rva};
use pe_edit::error::Result;

/// Disassemble one section of `doc`, returning formatted instruction lines
/// `"<rva>: <bytes>  <text>"` (limited to `limit` instructions).
pub fn disassemble_section(
    doc: &PeDocument,
    section_index: usize,
    limit: usize,
) -> Result<Vec<String>> {
    let section = doc.sections.get(section_index).ok_or_else(|| {
        pe_edit::error::PeError::InvalidArgument("disassemble: no such section".into())
    })?;
    let bitness = match doc.arch {
        pe_edit::domain::Arch::Bit64 => 64,
        pe_edit::domain::Arch::Bit32 => 32,
    };
    let sec_start = section.header.virtual_address.get();
    let mut decoder = Decoder::with_ip(
        bitness,
        &section.data,
        sec_start as u64,
        DecoderOptions::NONE,
    );
    let mut formatter = NasmFormatter::new();
    let mut out = Vec::new();
    let mut count = 0usize;
    while decoder.can_decode() && count < limit {
        let insn = decoder.decode();
        let mut text = String::new();
        formatter.format(&insn, &mut text);
        let start = (insn.ip() as u32 - sec_start) as usize;
        let end = (start + insn.len()).min(section.data.len());
        let bytes: Vec<String> = section.data[start..end]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        out.push(format!(
            "{:#08x}: {:<24} {}",
            insn.ip() as u32,
            bytes.join(" "),
            text
        ));
        count += 1;
    }
    Ok(out)
}

/// Format an instruction-free line for an RVA (used for jump-table entries).
#[allow(dead_code)]
pub fn rva_label(rva: Rva) -> String {
    format!("{:#x}", rva.get())
}
