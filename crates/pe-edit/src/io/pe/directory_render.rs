//! Renderers for the resource / relocation / TLS directories (the inverse of
//! the parser's directory parsers), used by the writer to persist edits made to
//! the rich forms.

use crate::domain::load_config::LoadConfigDirectory;
use crate::domain::resource::{ResourceDirectory, ResourceEntryData, ResourceName};
use crate::domain::types::Arch;
use crate::domain::{RelocationTable, TlsDirectory};
use crate::error::{PeError, Result};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_LOAD_CONFIG_DIRECTORY32, IMAGE_LOAD_CONFIG_DIRECTORY64,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_BASE_RELOCATION, IMAGE_TLS_DIRECTORY32, IMAGE_TLS_DIRECTORY32_0, IMAGE_TLS_DIRECTORY64,
    IMAGE_TLS_DIRECTORY64_0,
};

use super::write_struct;

/// Render a TLS directory into its on-disk bytes (48 for PE32+, 24 for PE32).
pub fn render_tls(tls: &TlsDirectory, arch: Arch) -> Vec<u8> {
    let mut out = Vec::new();
    if arch == Arch::Bit64 {
        let h = IMAGE_TLS_DIRECTORY64 {
            StartAddressOfRawData: tls.start_address_of_raw_data,
            EndAddressOfRawData: tls.end_address_of_raw_data,
            AddressOfIndex: tls.address_of_index,
            AddressOfCallBacks: tls.address_of_callbacks,
            SizeOfZeroFill: tls.size_of_zero_fill,
            Anonymous: IMAGE_TLS_DIRECTORY64_0 {
                Characteristics: tls.characteristics,
            },
        };
        write_struct(&mut out, &h);
    } else {
        let h = IMAGE_TLS_DIRECTORY32 {
            StartAddressOfRawData: tls.start_address_of_raw_data as u32,
            EndAddressOfRawData: tls.end_address_of_raw_data as u32,
            AddressOfIndex: tls.address_of_index as u32,
            AddressOfCallBacks: tls.address_of_callbacks as u32,
            SizeOfZeroFill: tls.size_of_zero_fill,
            Anonymous: IMAGE_TLS_DIRECTORY32_0 {
                Characteristics: tls.characteristics,
            },
        };
        write_struct(&mut out, &h);
    }
    out
}

/// Render a relocation table: blocks of `(page, size, entries…)` plus the
/// zero terminator block.
pub fn render_relocations(table: &RelocationTable) -> Vec<u8> {
    let mut out = Vec::new();
    for block in &table.blocks {
        let size = (8 + block.entries.len() * 2) as u32;
        let h = IMAGE_BASE_RELOCATION {
            VirtualAddress: block.page_rva.get(),
            SizeOfBlock: size,
        };
        write_struct(&mut out, &h);
        for e in &block.entries {
            let v = ((e.reloc_type as u16) << 12) | (e.offset & 0x0fff);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    write_struct(
        &mut out,
        &IMAGE_BASE_RELOCATION {
            VirtualAddress: 0,
            SizeOfBlock: 0,
        },
    );
    out
}

/// Render a load configuration directory. The `size` field is kept as-is; the
/// remainder of the structure is zeroed.
pub fn render_load_config(lc: &LoadConfigDirectory, arch: Arch) -> Vec<u8> {
    let mut out = Vec::new();
    if arch == Arch::Bit64 {
        let h = IMAGE_LOAD_CONFIG_DIRECTORY64 {
            Size: lc.size,
            TimeDateStamp: lc.time_date_stamp,
            MajorVersion: lc.major_version,
            MinorVersion: lc.minor_version,
            GlobalFlagsClear: lc.global_flags_clear,
            GlobalFlagsSet: lc.global_flags_set,
            SecurityCookie: lc.security_cookie,
            SEHandlerTable: lc.se_handler_table,
            SEHandlerCount: lc.se_handler_count,
            GuardCFCheckFunctionPointer: lc.guard_cf_check_function_pointer,
            GuardCFDispatchFunctionPointer: lc.guard_cf_dispatch_function_pointer,
            GuardCFFunctionTable: lc.guard_cf_function_table,
            GuardCFFunctionCount: lc.guard_cf_function_count,
            GuardFlags: lc.guard_flags,
            GuardAddressTakenIatEntryTable: lc.guard_address_taken_iat_entry_table,
            GuardAddressTakenIatEntryCount: lc.guard_address_taken_iat_entry_count,
            GuardLongJumpTargetTable: lc.guard_long_jump_target_table,
            GuardLongJumpTargetCount: lc.guard_long_jump_target_count,
            GuardEHContinuationTable: lc.guard_eh_continuation_table,
            GuardEHContinuationCount: lc.guard_eh_continuation_count,
            GuardXFGCheckFunctionPointer: lc.guard_xfg_check_function_pointer,
            GuardXFGDispatchFunctionPointer: lc.guard_xfg_dispatch_function_pointer,
            CHPEMetadataPointer: lc.chpe_metadata_pointer,
            HotPatchTableOffset: lc.hot_patch_table_offset,
            ..Default::default()
        };
        write_struct(&mut out, &h);
    } else {
        let h = IMAGE_LOAD_CONFIG_DIRECTORY32 {
            Size: lc.size,
            TimeDateStamp: lc.time_date_stamp,
            MajorVersion: lc.major_version,
            MinorVersion: lc.minor_version,
            GlobalFlagsClear: lc.global_flags_clear,
            GlobalFlagsSet: lc.global_flags_set,
            SecurityCookie: lc.security_cookie as u32,
            SEHandlerTable: lc.se_handler_table as u32,
            SEHandlerCount: lc.se_handler_count as u32,
            GuardCFCheckFunctionPointer: lc.guard_cf_check_function_pointer as u32,
            GuardCFDispatchFunctionPointer: lc.guard_cf_dispatch_function_pointer as u32,
            GuardCFFunctionTable: lc.guard_cf_function_table as u32,
            GuardCFFunctionCount: lc.guard_cf_function_count as u32,
            GuardFlags: lc.guard_flags,
            GuardAddressTakenIatEntryTable: lc.guard_address_taken_iat_entry_table as u32,
            GuardAddressTakenIatEntryCount: lc.guard_address_taken_iat_entry_count as u32,
            GuardLongJumpTargetTable: lc.guard_long_jump_target_table as u32,
            GuardLongJumpTargetCount: lc.guard_long_jump_target_count as u32,
            GuardEHContinuationTable: lc.guard_eh_continuation_table as u32,
            GuardEHContinuationCount: lc.guard_eh_continuation_count as u32,
            GuardXFGCheckFunctionPointer: lc.guard_xfg_check_function_pointer as u32,
            GuardXFGDispatchFunctionPointer: lc.guard_xfg_dispatch_function_pointer as u32,
            CHPEMetadataPointer: lc.chpe_metadata_pointer as u32,
            HotPatchTableOffset: lc.hot_patch_table_offset,
            ..Default::default()
        };
        write_struct(&mut out, &h);
    }
    out
}

/// Render a resource directory tree. Offsets inside the tree are relative to
/// the rendered blob's base; each leaf's data entry keeps the absolute RVA of
/// its content, which lives elsewhere in the image (preserved sections or
/// freshly allocated space).
pub fn render_resources(root: &ResourceDirectory) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_resource_dir(root, 0, &mut out)?;
    Ok(out)
}

const MAX_RENDER_RESOURCE_DEPTH: usize = 8;

fn write_resource_dir(dir: &ResourceDirectory, depth: usize, out: &mut Vec<u8>) -> Result<usize> {
    if depth > MAX_RENDER_RESOURCE_DEPTH {
        return Err(PeError::InvalidArgument("resource tree too deep".into()));
    }
    let dir_off = out.len();
    out.extend_from_slice(&[0u8; 16]);

    // Reserve a slot for every entry up front, so a subdirectory rendered for
    // one entry can never overwrite a later entry's placeholder.
    let entry_offs: Vec<usize> = (0..dir.entries.len())
        .map(|_| {
            let off = out.len();
            out.extend_from_slice(&[0u8; 8]);
            off
        })
        .collect();

    let named = dir
        .entries
        .iter()
        .filter(|e| matches!(e.name, ResourceName::Named(_)))
        .count();
    let ids = dir.entries.len() - named;
    out[dir_off + 12..dir_off + 14].copy_from_slice(&(named as u16).to_le_bytes());
    out[dir_off + 14..dir_off + 16].copy_from_slice(&(ids as u16).to_le_bytes());

    for (i, entry) in dir.entries.iter().enumerate() {
        let entry_off = entry_offs[i];
        let name_field = match &entry.name {
            ResourceName::Id(id) => *id,
            ResourceName::Named(name) => {
                let str_off = rel_offset(out.len())?;
                let units: Vec<u16> = name.encode_utf16().collect();
                if units.len() > u16::MAX as usize {
                    return Err(PeError::InvalidArgument("resource name too long".into()));
                }
                out.extend_from_slice(&(units.len() as u16).to_le_bytes());
                for u in &units {
                    out.extend_from_slice(&u.to_le_bytes());
                }
                0x8000_0000 | str_off
            }
        };
        let data_field = match &entry.data {
            ResourceEntryData::Directory(sub) => {
                let sub_off = rel_offset(write_resource_dir(sub, depth + 1, out)?)?;
                0x8000_0000 | sub_off
            }
            ResourceEntryData::Leaf(leaf) => {
                let data_entry_off = rel_offset(out.len())?;
                out.extend_from_slice(&leaf.rva.get().to_le_bytes());
                out.extend_from_slice(&leaf.size.to_le_bytes());
                out.extend_from_slice(&leaf.code_page.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes()); // reserved
                data_entry_off
            }
        };
        out[entry_off..entry_off + 4].copy_from_slice(&name_field.to_le_bytes());
        out[entry_off + 4..entry_off + 8].copy_from_slice(&data_field.to_le_bytes());
    }
    Ok(dir_off)
}

/// A resource-internal offset must fit in 31 bits (the high bit flags name
/// strings and subdirectories).
fn rel_offset(off: usize) -> Result<u32> {
    if off > 0x7fff_ffff {
        return Err(PeError::InvalidArgument("resource table too large".into()));
    }
    Ok(off as u32)
}
