//! Save / load the curated import tree (and the OEP / IAT metadata) to a file
//! in **JSON** or **XML** — Scylla's "Save / Load Tree". Hand-rolled
//! (de)serializers, no serde dependency.
//!
//! The file captures the whole Get-Imports state so a dump can be analysed in
//! one session, the tree saved, and re-opened later without re-attaching to the
//! process. [`TreeFile`] carries the metadata plus the [`ImportsTree`].

use std::fmt::Write as _;
use std::path::Path;

use crate::api::{ImportEntry, ImportModule, ImportStatus, ImportsTree};
use crate::{PeError, Result};

/// A saved import tree plus the Scylla fields that belong with it.
#[derive(Debug, Clone, Default)]
pub struct TreeFile {
    pub oep: u32,
    pub iat_va: u64,
    pub iat_size: usize,
    pub tree: ImportsTree,
}

/// Save `file` to `path` as JSON (detected by extension or forced).
pub fn save_json(path: &Path, file: &TreeFile) -> Result<()> {
    std::fs::write(path, ser_json(file)?).map_err(PeError::Io)
}

/// Load a JSON tree file.
pub fn load_json(path: &Path) -> Result<TreeFile> {
    let bytes = std::fs::read(path).map_err(PeError::Io)?;
    de_json(&String::from_utf8_lossy(&bytes))
}

/// Save `file` to `path` as XML.
pub fn save_xml(path: &Path, file: &TreeFile) -> Result<()> {
    std::fs::write(path, ser_xml(file)).map_err(PeError::Io)
}

/// Load an XML tree file.
pub fn load_xml(path: &Path) -> Result<TreeFile> {
    let bytes = std::fs::read(path).map_err(PeError::Io)?;
    de_xml(&String::from_utf8_lossy(&bytes))
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn ser_json(file: &TreeFile) -> Result<String> {
    let mut out = String::new();
    out.push_str("{\"oep\":");
    let _ = write!(out, "{}", file.oep);
    out.push_str(",\"iat_va\":");
    let _ = write!(out, "{}", file.iat_va);
    out.push_str(",\"iat_size\":");
    let _ = write!(out, "{}", file.iat_size);
    out.push_str(",\"modules\":[");
    for (i, m) in file.tree.modules.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"name\":\"{}\",\"first_thunk\":{}",
            esc(&m.name),
            m.first_thunk
        );
        out.push_str(",\"entries\":[");
        for (j, e) in m.entries.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"slot_va\":{},\"slot_rva\":{},\"api_address\":{},\"module\":\"{}\",\"name\":\"{}\",\"ordinal\":{},\"hint\":{},\"status\":\"{}\"}}",
                e.slot_va,
                e.slot_rva,
                e.api_address,
                esc(&e.module),
                esc(&e
                    .function
                    .as_ref()
                    .map(|f| f.display_name())
                    .unwrap_or_default()),
                e.function.as_ref().and_then(|f| f.ordinal()).unwrap_or(0),
                0u16, // hint is not tracked on the resolved entry
                status_name(e.status),
            );
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    Ok(out)
}

/// Escape a JSON string value (quotes + backslashes + control chars).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn status_name(s: ImportStatus) -> &'static str {
    match s {
        ImportStatus::Valid => "valid",
        ImportStatus::Suspect => "suspect",
        ImportStatus::Invalid => "invalid",
    }
}

fn status_from(s: &str) -> ImportStatus {
    match s {
        "suspect" => ImportStatus::Suspect,
        "invalid" => ImportStatus::Invalid,
        _ => ImportStatus::Valid,
    }
}

/// Minimal recursive-descent JSON parser for the tree-file schema.
fn de_json(text: &str) -> Result<TreeFile> {
    let mut p = JsonParser {
        b: text.as_bytes(),
        i: 0,
    };
    p.skip_ws();
    if p.peek() != Some(b'{') {
        return Err(PeError::Malformed("tree JSON: expected object".into()));
    }
    let mut file = TreeFile::default();
    p.object(|key, p| match key {
        "oep" => {
            file.oep = p.number()? as u32;
            Ok(())
        }
        "iat_va" => {
            file.iat_va = p.number()?;
            Ok(())
        }
        "iat_size" => {
            file.iat_size = p.number()? as usize;
            Ok(())
        }
        "modules" => {
            file.tree = p.modules()?;
            Ok(())
        }
        _ => p.skip_value(),
    })?;
    Ok(file)
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> JsonParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn skip_ws(&mut self) {
        while matches!(
            self.peek(),
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
        ) {
            self.i += 1;
        }
    }
    fn expect(&mut self, c: u8) -> Result<()> {
        self.skip_ws();
        if self.peek() != Some(c) {
            return Err(PeError::Malformed(format!(
                "tree JSON: expected '{}'",
                c as char
            )));
        }
        self.i += 1;
        Ok(())
    }
    fn number(&mut self) -> Result<u64> {
        self.skip_ws();
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i])
            .map_err(|_| PeError::Malformed("tree JSON: bad number".into()))?;
        s.parse::<u64>()
            .map_err(|_| PeError::Malformed("tree JSON: bad number".into()))
    }
    fn string(&mut self) -> Result<String> {
        self.skip_ws();
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(PeError::Malformed("tree JSON: unterminated string".into())),
                Some(b'"') => {
                    self.i += 1;
                    break;
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(b'"') => {
                            out.push('"');
                            self.i += 1;
                        }
                        Some(b'\\') => {
                            out.push('\\');
                            self.i += 1;
                        }
                        Some(b'n') => {
                            out.push('\n');
                            self.i += 1;
                        }
                        Some(b'r') => {
                            out.push('\r');
                            self.i += 1;
                        }
                        Some(b't') => {
                            out.push('\t');
                            self.i += 1;
                        }
                        Some(b'u') => {
                            let hex = std::str::from_utf8(&self.b[self.i + 1..self.i + 5])
                                .ok()
                                .and_then(|s| u32::from_str_radix(s, 16).ok())
                                .unwrap_or(0);
                            if let Some(c) = char::from_u32(hex) {
                                out.push(c);
                            }
                            self.i += 5;
                        }
                        _ => {
                            return Err(PeError::Malformed("tree JSON: bad escape".into()));
                        }
                    }
                }
                Some(c) => {
                    out.push(c as char);
                    self.i += 1;
                }
            }
        }
        Ok(out)
    }
    /// Read an object body, calling `f` per `"key": value` pair.
    fn object(&mut self, mut f: impl FnMut(&str, &mut Self) -> Result<()>) -> Result<()> {
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.expect(b':')?;
            f(&key, self)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(PeError::Malformed("tree JSON: expected ',' or '}'".into())),
            }
        }
        Ok(())
    }
    fn array<T>(&mut self, mut item: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        self.expect(b'[')?;
        self.skip_ws();
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(out);
        }
        loop {
            out.push(item(self)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                c => {
                    return Err(PeError::Malformed(format!(
                        "tree JSON: expected ',' or ']' at byte {} (found {:?})",
                        self.i,
                        c.map(char::from)
                    )));
                }
            }
        }
        Ok(out)
    }
    fn skip_value(&mut self) -> Result<()> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') | Some(b'[') => {
                // balanced skip
                let mut depth = 1usize;
                let mut in_str = false;
                self.i += 1;
                while let Some(c) = self.peek() {
                    self.i += 1;
                    if in_str {
                        if c == b'\\' {
                            self.i += 1;
                        } else if c == b'"' {
                            in_str = false;
                        }
                        continue;
                    }
                    match c {
                        b'"' => in_str = true,
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(())
            }
            _ => {
                while matches!(
                    self.peek(),
                    Some(b'0'..=b'9') | Some(b'-') | Some(b'.') | Some(b'e') | Some(b'E')
                ) {
                    self.i += 1;
                }
                if self.peek() == Some(b'"') {
                    self.string()?;
                }
                Ok(())
            }
        }
    }
    fn modules(&mut self) -> Result<ImportsTree> {
        let modules = self.array(|p| {
            let mut module = ImportModule {
                name: String::new(),
                first_thunk: 0,
                entries: Vec::new(),
            };
            p.object(|key, p| match key {
                "name" => {
                    module.name = p.string()?;
                    Ok(())
                }
                "first_thunk" => {
                    module.first_thunk = p.number()?;
                    Ok(())
                }
                "entries" => {
                    module.entries = p.array(|p| p.entry())?;
                    Ok(())
                }
                _ => p.skip_value(),
            })?;
            Ok(module)
        })?;
        Ok(ImportsTree { modules })
    }
    fn entry(&mut self) -> Result<ImportEntry> {
        let mut e = ImportEntry {
            slot_va: 0,
            slot_rva: 0,
            api_address: 0,
            function: None,
            module: String::new(),
            status: ImportStatus::Invalid,
        };
        self.object(|key, p| match key {
            "slot_va" => {
                e.slot_va = p.number()?;
                Ok(())
            }
            "slot_rva" => {
                e.slot_rva = p.number()? as u32;
                Ok(())
            }
            "api_address" => {
                e.api_address = p.number()?;
                Ok(())
            }
            "module" => {
                e.module = p.string()?;
                Ok(())
            }
            "name" => {
                let name = p.string()?;
                e.function = Some(pe_edit::domain::ImportFunction::by_name(name));
                Ok(())
            }
            "ordinal" => {
                let ord = p.number()? as u16;
                if e.function.is_none() && ord != 0 {
                    e.function = Some(pe_edit::domain::ImportFunction::by_ordinal(ord));
                }
                Ok(())
            }
            "status" => {
                e.status = status_from(&p.string()?);
                Ok(())
            }
            _ => p.skip_value(),
        })?;
        Ok(e)
    }
}

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------

fn ser_xml(file: &TreeFile) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "<Scylla oep=\"0x{:x}\" iat_va=\"0x{:x}\" iat_size=\"0x{:x}\">",
        file.oep, file.iat_va, file.iat_size
    );
    for m in &file.tree.modules {
        let _ = writeln!(
            out,
            "  <Module name=\"{}\" first_thunk=\"0x{:x}\">",
            esc(&m.name),
            m.first_thunk
        );
        for e in &m.entries {
            let _ = writeln!(
                out,
                "    <Import slot_va=\"0x{:x}\" slot_rva=\"0x{:x}\" api_address=\"0x{:x}\" module=\"{}\" name=\"{}\" ordinal=\"{}\" status=\"{}\"/>",
                e.slot_va,
                e.slot_rva,
                e.api_address,
                esc(&e.module),
                esc(&e
                    .function
                    .as_ref()
                    .map(|f| f.display_name())
                    .unwrap_or_default()),
                e.function.as_ref().and_then(|f| f.ordinal()).unwrap_or(0),
                status_name(e.status),
            );
        }
        out.push_str("  </Module>\n");
    }
    out.push_str("</Scylla>\n");
    out
}

/// Minimal XML tag scanner for the tree-file schema.
fn de_xml(text: &str) -> Result<TreeFile> {
    let mut file = TreeFile::default();
    let mut i = 0usize;
    let b = text.as_bytes();
    let peek = |i: usize, needle: &[u8]| b[i..].starts_with(needle);
    let attr = |tag: &str, name: &str| -> Option<String> {
        let key = format!("{name}=\"");
        let start = tag.find(&key)? + key.len();
        let rest = &tag[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    };
    let attr_u64 = |tag: &str, name: &str| attr(tag, name).and_then(|s| parse_hex(&s));

    while i < b.len() {
        if !peek(i, b"<Module") {
            i += 1;
            continue;
        }
        let end = text[i..].find('>').map(|e| i + e).unwrap_or(b.len());
        let tag = &text[i + 1..end];
        let module_name = attr(tag, "name").unwrap_or_default();
        let first_thunk = attr_u64(tag, "first_thunk").unwrap_or(0);
        i = end + 1;
        // Collect <Import .../> until </Module>
        let mut entries = Vec::new();
        loop {
            if peek(i, b"</Module") {
                break;
            }
            if !peek(i, b"<Import") {
                i += 1;
                if i >= b.len() {
                    break;
                }
                continue;
            }
            let e = text[i..].find('>').map(|e| i + e).unwrap_or(b.len());
            let itag = &text[i + 1..e];
            let name = attr(itag, "name").unwrap_or_default();
            let function = if name.is_empty() {
                attr_u64(itag, "ordinal")
                    .map(|o| pe_edit::domain::ImportFunction::by_ordinal(o as u16))
            } else {
                Some(pe_edit::domain::ImportFunction::by_name(name))
            };
            entries.push(ImportEntry {
                slot_va: attr_u64(itag, "slot_va").unwrap_or(0),
                slot_rva: attr_u64(itag, "slot_rva").unwrap_or(0) as u32,
                api_address: attr_u64(itag, "api_address").unwrap_or(0),
                module: attr(itag, "module").unwrap_or_default(),
                function,
                status: status_from(&attr(itag, "status").unwrap_or_default()),
            });
            i = e + 1;
        }
        file.tree.modules.push(ImportModule {
            name: module_name,
            first_thunk,
            entries,
        });
        if peek(i, b"</Module") {
            i = text[i..].find('>').map(|e| i + e + 1).unwrap_or(b.len());
        }
    }
    // Metadata from the root tag (first `<Scylla ...>`).
    if let Some(start) = text.find("<Scylla") {
        let end = text[start..]
            .find('>')
            .map(|e| start + e)
            .unwrap_or(b.len());
        let tag = &text[start + 1..end];
        file.oep = attr_u64(tag, "oep").unwrap_or(0) as u32;
        file.iat_va = attr_u64(tag, "iat_va").unwrap_or(0);
        file.iat_size = attr_u64(tag, "iat_size").unwrap_or(0) as usize;
    }
    Ok(file)
}

/// Parse `0x...` or decimal.
fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}
