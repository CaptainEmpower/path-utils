//! Error types for path utility operations

use thiserror::Error;

/// The error type for path utility operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum PathError {
    /// Path traversal attack detected (contains .. components)
    #[error("Path traversal detected: {path} - relative paths with '..' are not allowed")]
    PathTraversal { path: String },

    /// Empty or whitespace-only path
    #[error("Empty paths are not allowed")]
    EmptyPath,

    /// Invalid characters detected in path
    #[error("Invalid characters detected in path: {path}")]
    InvalidCharacters { path: String },

    /// Reserved filename (Windows compatibility)
    #[error("Reserved filename detected: {filename} in path {path}")]
    ReservedFilename { filename: String, path: String },

    /// Windows drive letter path
    #[error("Drive letter paths are not allowed: {path}")]
    DriveLetterPath { path: String },

    /// General path validation failure
    #[error("Path validation failed: {message}")]
    ValidationFailed { message: String },

    /// Path construction failure
    #[error("Path construction failed: {message}")]
    ConstructionFailed { message: String },

    /// I/O error during path operations
    #[error("I/O error: {message}")]
    IoError { message: String },
}

impl From<std::io::Error> for PathError {
    fn from(err: std::io::Error) -> Self {
        PathError::IoError {
            message: err.to_string(),
        }
    }
}

/// Result type for path utility operations
pub type Result<T> = std::result::Result<T, PathError>;