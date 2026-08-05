//! Error type for the whole crate.

use thiserror::Error;

/// The crate's unified error type.
#[derive(Debug, Error)]
pub enum PeError {
    /// A code path that has not been implemented yet (used while the outer API
    /// is being fixed before the real parser lands).
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),

    /// The input bytes do not form a valid PE file.
    #[error("malformed PE: {0}")]
    Malformed(String),

    /// An operation is not supported for this file/architecture.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// A caller-supplied argument is invalid.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// I/O failed while reading/writing a file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, PeError>;
