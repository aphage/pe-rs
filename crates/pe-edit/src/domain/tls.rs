//! Thread-local storage directory (`IMAGE_TLS_DIRECTORY`).

/// The TLS directory, with address fields widened to `u64` for both PE32 and
/// PE32+.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}
