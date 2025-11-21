//! # path-utils
//!
//! Secure, cross-platform path normalization and validation utilities.
//!
//! This crate provides robust path manipulation functions with a focus on security
//! and cross-platform compatibility. Originally developed for git-mvh but designed
//! to be useful for any application that needs safe path handling.
//!
//! ## Features
//!
//! - **Path Normalization**: Consistent slash handling across platforms
//! - **Security Validation**: Path traversal attack prevention
//! - **Sanitization**: Convert absolute paths to relative paths safely
//! - **Cross-platform**: Works consistently on Windows, macOS, and Linux
//! - **Zero Dependencies**: Minimal dependency footprint
//!
//! ## Examples
//!
//! ### Basic Path Normalization
//!
//! ```rust
//! use path_utils::{normalize_path_str, join_and_normalize};
//! use std::path::PathBuf;
//!
//! // Normalize path separators and remove double slashes
//! assert_eq!(normalize_path_str("a//b\\c"), "a/b/c");
//!
//! // Join paths safely
//! let result = join_and_normalize("source/", "/main.rs");
//! assert_eq!(result, PathBuf::from("source/main.rs"));
//! ```
//!
//! ### Security-Focused Path Sanitization
//!
//! ```rust
//! use path_utils::{sanitize_directory_file_path, safe_repository_join};
//! use std::path::Path;
//!
//! // Convert absolute paths to relative (useful for directory content parsing)
//! let sanitized = sanitize_directory_file_path("/args.js").unwrap();
//! assert_eq!(sanitized, "args.js");
//!
//! // Safely join repository paths with validation
//! let temp_dir = std::env::temp_dir();
//! let safe_path = safe_repository_join(&temp_dir, "project", "/config.js").unwrap();
//! // Result: {temp_dir}/project/config.js (not root filesystem!)
//! ```
//!
//! ### Path Traversal Prevention
//!
//! ```rust
//! use path_utils::sanitize_directory_file_path;
//!
//! // These will return errors due to security violations
//! assert!(sanitize_directory_file_path("../etc/passwd").is_err());
//! assert!(sanitize_directory_file_path("").is_err());
//! assert!(sanitize_directory_file_path("file\0null").is_err());
//! ```

mod error;
mod normalize;
mod validate;

// Generators module for property testing (available in tests)
#[cfg(test)]
pub mod generators;

// Re-export main public API
pub use error::{PathError, Result};
pub use normalize::{
    join_and_normalize, normalize_path_buf, normalize_path_str, safe_repository_join,
    sanitize_directory_file_path,
};
pub use validate::{is_safe_path, validate_path};

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");