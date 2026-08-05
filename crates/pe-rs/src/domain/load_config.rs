//! Load configuration directory (`IMAGE_LOAD_CONFIG_DIRECTORY`).
//!
//! The structure is variable-length: the `size` field says how many bytes are
//! actually present, so fields beyond it are not meaningful.

/// `IMAGE_GUARD_*` flag bits (Control Flow Guard).
pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
pub const IMAGE_GUARD_CFW_INSTRUMENTED: u32 = 0x0000_0200;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
pub const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_4000;

/// The load configuration directory, with address fields widened to `u64` for
/// both PE32 and PE32+.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadConfigDirectory {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub security_cookie: u64,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_cf_check_function_pointer: u64,
    pub guard_cf_dispatch_function_pointer: u64,
    pub guard_cf_function_table: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
    pub guard_address_taken_iat_entry_table: u64,
    pub guard_address_taken_iat_entry_count: u64,
    pub guard_long_jump_target_table: u64,
    pub guard_long_jump_target_count: u64,
    pub guard_eh_continuation_table: u64,
    pub guard_eh_continuation_count: u64,
    pub guard_xfg_check_function_pointer: u64,
    pub guard_xfg_dispatch_function_pointer: u64,
    pub chpe_metadata_pointer: u64,
    pub hot_patch_table_offset: u32,
}
