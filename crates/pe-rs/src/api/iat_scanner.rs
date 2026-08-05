//! IAT scanning.

use crate::api::resolver::ImportResolver;
use crate::domain::types::ptr_size;
use crate::domain::{IatEntry, IatScan, PeDocument, Rva, ScanMethod, ScanOptions};
use crate::error::{PeError, Result};

/// Locates a candidate Import Address Table in a [`PeDocument`].
///
/// The default method walks the document's image (or a `region` window) slot by
/// slot and keeps maximal runs whose stored value resolves through
/// [`ImportResolver`]. Entries whose value cannot be resolved (unmapped slots,
/// zero, or data) terminate a run.
pub trait IatScanner {
    fn scan(&self, resolver: &dyn ImportResolver, options: &ScanOptions) -> Result<IatScan>;
}

impl IatScanner for PeDocument {
    fn scan(&self, resolver: &dyn ImportResolver, options: &ScanOptions) -> Result<IatScan> {
        match options.method {
            ScanMethod::Resolver => self.scan_by_resolver(resolver, options),
            ScanMethod::OpcodePattern => {
                Err(PeError::NotImplemented("IatScanner::scan (OpcodePattern)"))
            }
        }
    }
}

struct Run {
    base: Rva,
    entries: Vec<IatEntry>,
}

impl PeDocument {
    fn scan_by_resolver(
        &self,
        resolver: &dyn ImportResolver,
        options: &ScanOptions,
    ) -> Result<IatScan> {
        let psize = ptr_size(self.arch);

        let (start, len) = match options.region {
            Some((rva, len)) => (rva, len),
            None => {
                let (s0, e0) = self
                    .sections
                    .iter()
                    .fold((u32::MAX, 0u32), |(s0, e0), sec| {
                        let s = sec.header.virtual_address.get();
                        let e = s.saturating_add(sec.data.len() as u32);
                        (s0.min(s), e0.max(e))
                    });
                if e0 <= s0 {
                    return Err(PeError::NotFound("image has no mappable data".into()));
                }
                (Rva(s0), (e0 - s0) as usize)
            }
        };

        let mut current: Option<Run> = None;
        let mut best: Option<Run> = None;

        for off in (0..len).step_by(psize) {
            let Some(slot_rva) = start.checked_add(off as u32) else { break };
            let slot_val = self.read(slot_rva, psize).ok().and_then(|b| {
                let v = if psize == 8 {
                    u64::from_le_bytes(b.try_into().unwrap())
                } else {
                    u32::from_le_bytes(b.try_into().unwrap()) as u64
                };
                resolver.resolve(v).map(|_| v)
            });

            match slot_val {
                Some(v) => {
                    let run = current.get_or_insert_with(|| Run { base: slot_rva, entries: Vec::new() });
                    run.entries.push(IatEntry { rva: slot_rva, value: v });
                }
                None => {
                    if let Some(run) = current.take() {
                        consider(run, options.min_entries, &mut best);
                    }
                }
            }
        }
        if let Some(run) = current.take() {
            consider(run, options.min_entries, &mut best);
        }

        match best {
            Some(run) => Ok(IatScan {
                base_rva: run.base,
                size: run.entries.len(),
                entries: run.entries,
            }),
            None => Err(PeError::NotFound(format!(
                "no IAT run with >= {} resolvable entries found",
                options.min_entries
            ))),
        }
    }
}

fn consider(run: Run, min_entries: usize, best: &mut Option<Run>) {
    if run.entries.len() >= min_entries
        && best.as_ref().is_none_or(|b| run.entries.len() > b.entries.len())
    {
        *best = Some(run);
    }
}
