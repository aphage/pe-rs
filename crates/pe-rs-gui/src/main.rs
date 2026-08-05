//! Placeholder binary that consumes the `pe-rs` library from a downstream
//! crate, proving the public API is usable outside the library itself.

use pe_rs::api::PeViewer;
use pe_rs::io::MockSource;

fn main() {
    let doc = MockSource::document();
    println!("pe-rs-gui placeholder — consumes the pe-rs library.");
    println!(
        "Loaded mock PE: arch={:?}, sections={}, imports={}, exports={}",
        doc.arch(),
        doc.sections().len(),
        doc.imports().len(),
        doc.exports().map(|e| e.symbols.len()).unwrap_or(0),
    );
}
