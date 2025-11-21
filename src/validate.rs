//! Path validation utilities
//!
//! Additional validation functions for path safety checks.

use crate::error::{PathError, Result};
use std::path::Path;

/// Check if a path is safe for use
///
/// This performs basic safety checks on a path without modifying it.
/// Useful for validation before path operations.
///
/// # Examples
/// ```
/// use path_utils::is_safe_path;
///
/// assert!(is_safe_path("safe/path/file.txt"));
/// assert!(!is_safe_path("../etc/passwd"));
/// assert!(!is_safe_path(""));
/// ```
pub fn is_safe_path<P: AsRef<Path>>(path: P) -> bool {
    let path_str = path.as_ref().to_string_lossy();

    // Check for empty paths
    if path_str.trim().is_empty() {
        return false;
    }

    // Check for path traversal
    if path_str.contains("..") {
        return false;
    }

    // Check for null bytes and dangerous control characters
    if path_str.contains('\0')
        || path_str
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return false;
    }

    // Check for Windows-problematic characters
    for invalid_char in ['<', '>', '|', '?', '*', '"'] {
        if path_str.contains(invalid_char) {
            return false;
        }
    }

    // Check for Windows reserved names
    let reserved_names = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    for component in path_str.split('/').chain(path_str.split('\\')) {
        let component_upper = component.to_uppercase();
        let base_name = component_upper.split('.').next().unwrap_or("");
        if reserved_names.contains(&base_name) {
            return false;
        }
    }

    true
}

/// Validate a path and return detailed error information
///
/// This function performs comprehensive validation and returns specific error types
/// for different validation failures.
///
/// # Examples
/// ```
/// use path_utils::validate_path;
///
/// assert!(validate_path("safe/path/file.txt").is_ok());
/// assert!(validate_path("../etc/passwd").is_err());
/// ```
pub fn validate_path<P: AsRef<Path>>(path: P) -> Result<()> {
    let path_str = path.as_ref().to_string_lossy();
    let path_string = path_str.to_string();

    // Check for empty paths
    if path_str.trim().is_empty() {
        return Err(PathError::EmptyPath);
    }

    // Check for path traversal
    if path_str.contains("..") {
        return Err(PathError::PathTraversal { path: path_string });
    }

    // Check for null bytes and dangerous control characters
    if path_str.contains('\0')
        || path_str
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(PathError::InvalidCharacters { path: path_string });
    }

    // Check for Windows-problematic characters
    for invalid_char in ['<', '>', '|', '?', '*', '"'] {
        if path_str.contains(invalid_char) {
            return Err(PathError::InvalidCharacters { path: path_string });
        }
    }

    // Check for Windows reserved names
    let reserved_names = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    for component in path_str.split('/').chain(path_str.split('\\')) {
        let component_upper = component.to_uppercase();
        let base_name = component_upper.split('.').next().unwrap_or("");
        if reserved_names.contains(&base_name) {
            return Err(PathError::ReservedFilename {
                filename: component.to_string(),
                path: path_string,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_path() {
        // Safe paths
        assert!(is_safe_path("safe/path/file.txt"));
        assert!(is_safe_path("file.txt"));
        assert!(is_safe_path("src/main.rs"));

        // Unsafe paths
        assert!(!is_safe_path("../etc/passwd"));
        assert!(!is_safe_path(""));
        assert!(!is_safe_path("   "));
        assert!(!is_safe_path("file\0null"));
        assert!(!is_safe_path("file<script>"));
        assert!(!is_safe_path("CON"));
        assert!(!is_safe_path("PRN.txt"));
    }

    #[test]
    fn test_validate_path() {
        // Valid paths
        assert!(validate_path("safe/path/file.txt").is_ok());
        assert!(validate_path("file.txt").is_ok());
        assert!(validate_path("src/main.rs").is_ok());

        // Invalid paths with specific errors
        assert!(matches!(
            validate_path("../etc/passwd"),
            Err(PathError::PathTraversal { .. })
        ));
        assert!(matches!(validate_path(""), Err(PathError::EmptyPath)));
        assert!(matches!(validate_path("   "), Err(PathError::EmptyPath)));
        assert!(matches!(
            validate_path("file\0null"),
            Err(PathError::InvalidCharacters { .. })
        ));
        assert!(matches!(
            validate_path("file<script>"),
            Err(PathError::InvalidCharacters { .. })
        ));
        assert!(matches!(
            validate_path("CON"),
            Err(PathError::ReservedFilename { .. })
        ));
        assert!(matches!(
            validate_path("PRN.txt"),
            Err(PathError::ReservedFilename { .. })
        ));
    }
}