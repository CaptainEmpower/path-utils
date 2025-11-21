//! Path normalization and sanitization functions
//!
//! This module provides robust path manipulation functions with security as a primary concern.

use crate::error::{PathError, Result};
use std::path::{Path, PathBuf};

/// Normalize a path string for cross-platform compatibility and consistency
///
/// This function:
/// - Converts backslashes to forward slashes (Windows compatibility)
/// - Removes double slashes
/// - Removes empty path components
/// - Ensures consistent forward-slash separators
///
/// This is the canonical normalization function for all string-based path operations.
///
/// # Examples
/// ```
/// use path_utils::normalize_path_str;
///
/// assert_eq!(normalize_path_str("a//b"), "a/b");
/// assert_eq!(normalize_path_str("a\\b"), "a/b");
/// assert_eq!(normalize_path_str("a//b//c"), "a/b/c");
/// ```
pub fn normalize_path_str(path: &str) -> String {
    path.replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// Normalize a PathBuf to a consistent format
///
/// This function:
/// - Converts the path to a string
/// - Applies string normalization
/// - Converts back to PathBuf
///
/// Use this when you need a normalized PathBuf.
///
/// # Examples
/// ```
/// use path_utils::normalize_path_buf;
/// use std::path::PathBuf;
///
/// assert_eq!(normalize_path_buf("a//b"), PathBuf::from("a/b"));
/// assert_eq!(normalize_path_buf("a\\b"), PathBuf::from("a/b"));
/// ```
pub fn normalize_path_buf<P: AsRef<Path>>(path: P) -> PathBuf {
    let path_str = path.as_ref().to_string_lossy();
    let normalized_str = normalize_path_str(&path_str);
    PathBuf::from(normalized_str)
}

/// Join two paths and normalize the result
///
/// This is a safer alternative to `PathBuf::join()` that ensures the result
/// is normalized and doesn't contain double slashes.
///
/// # Examples
/// ```
/// use path_utils::join_and_normalize;
/// use std::path::PathBuf;
///
/// let base = PathBuf::from("source/");
/// let file = PathBuf::from("/main.rs");
/// let result = join_and_normalize(&base, &file);
/// assert_eq!(result, PathBuf::from("source/main.rs"));
/// ```
pub fn join_and_normalize<P1: AsRef<Path>, P2: AsRef<Path>>(base: P1, path: P2) -> PathBuf {
    let base_str = base.as_ref().to_string_lossy();
    let path_str = path.as_ref().to_string_lossy();

    // Remove trailing slash from base and leading slash from path
    let base_trimmed = base_str.trim_end_matches('/');
    let path_trimmed = path_str.trim_start_matches('/');

    if base_trimmed.is_empty() {
        normalize_path_buf(path_trimmed)
    } else if path_trimmed.is_empty() {
        normalize_path_buf(base_trimmed)
    } else {
        normalize_path_buf(format!("{}/{}", base_trimmed, path_trimmed))
    }
}

/// Sanitize a directory file path extracted from patch content
///
/// This function is specifically designed for directory content parsing where
/// file paths might be stored with absolute path markers that need to be
/// converted to relative paths for safe repository operations.
///
/// # Security
/// - Prevents path traversal attacks by validating path components
/// - Ensures paths are relative to repository root
/// - Cross-platform path normalization
///
/// # Examples
/// ```
/// use path_utils::sanitize_directory_file_path;
///
/// // Absolute path from directory content -> relative path
/// let result = sanitize_directory_file_path("/args.js").unwrap();
/// assert_eq!(result, "args.js");
///
/// // Already relative path -> unchanged
/// let result = sanitize_directory_file_path("lib/generator.js").unwrap();
/// assert_eq!(result, "lib/generator.js");
/// ```
pub fn sanitize_directory_file_path(path: &str) -> Result<String> {
    // Handle empty paths
    if path.trim().is_empty() {
        return Err(PathError::EmptyPath);
    }

    // Normalize the path first (handles backslashes, double slashes)
    let normalized = normalize_path_str(path);

    // Security: Prevent path traversal attacks
    if normalized.contains("..") {
        return Err(PathError::PathTraversal {
            path: path.to_string(),
        });
    }

    // Convert absolute paths to relative paths for repository context
    // This is the core fix for the CLI bug where directory content contains absolute paths
    let normalized = if normalized.starts_with('/') {
        normalized.trim_start_matches('/').to_string()
    } else {
        normalized
    };

    // Windows drive letters are also considered absolute
    if cfg!(windows) && normalized.len() > 1 && normalized.chars().nth(1) == Some(':') {
        return Err(PathError::DriveLetterPath {
            path: path.to_string(),
        });
    }

    // Security: Reject null bytes and control characters
    if normalized.contains('\0')
        || normalized
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(PathError::InvalidCharacters {
            path: path.to_string(),
        });
    }

    // Security: Reject paths that would be problematic on Windows
    // This ensures cross-platform compatibility
    for invalid_char in ['<', '>', '|', '?', '*', '"'] {
        if normalized.contains(invalid_char) {
            return Err(PathError::InvalidCharacters {
                path: path.to_string(),
            });
        }
    }

    // Security: Reject reserved Windows filenames (case-insensitive)
    let reserved_names = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    // Check each path component
    for component in normalized.split('/') {
        let component_upper = component.to_uppercase();
        // Check base name without extension
        let base_name = component_upper.split('.').next().unwrap_or("");
        if reserved_names.contains(&base_name) {
            return Err(PathError::ReservedFilename {
                filename: component.to_string(),
                path: path.to_string(),
            });
        }
    }

    Ok(normalized)
}

/// Safe repository path joining for directory content
///
/// This function combines repository workdir, target path, and a sanitized
/// file path from directory content to create a safe absolute file system path.
///
/// This is the canonical function for all directory content file path operations.
///
/// # Arguments
/// - `workdir`: Repository working directory (absolute path)
/// - `target_path`: Target directory within repository (relative)
/// - `file_path`: File path from directory content (will be sanitized)
///
/// # Returns
/// Absolute file system path that is safe to write to
///
/// # Examples
/// ```
/// use path_utils::safe_repository_join;
/// use std::path::Path;
/// use tempfile::TempDir;
///
/// let temp_dir = TempDir::new().unwrap();
/// let workdir = temp_dir.path();
/// let target = Path::new("testing/framework");
/// let file = "/args.js";  // Absolute path from directory content
///
/// let result = safe_repository_join(workdir, target, file).unwrap();
/// assert!(result.to_string_lossy().ends_with("testing/framework/args.js"));
/// ```
pub fn safe_repository_join<P1: AsRef<Path>, P2: AsRef<Path>>(
    workdir: P1,
    target_path: P2,
    file_path: &str,
) -> Result<PathBuf> {
    // Sanitize the file path from directory content
    let sanitized_file_path = sanitize_directory_file_path(file_path)?;

    // Canonicalize workdir early to handle symlinks
    let workdir_canonical = workdir
        .as_ref()
        .canonicalize()
        .map_err(|e| PathError::IoError {
            message: format!("Cannot canonicalize workdir: {}", e),
        })?;

    // Use standard library path operations for absolute paths to preserve leading slash
    let target_normalized = normalize_path_buf(target_path.as_ref());
    let file_normalized = PathBuf::from(sanitized_file_path);

    // Join canonical_workdir -> target -> file preserving absolute path
    let final_path = workdir_canonical
        .join(target_normalized)
        .join(file_normalized);

    // Basic validation: ensure the constructed path has no .. components
    let relative_to_workdir =
        final_path
            .strip_prefix(&workdir_canonical)
            .map_err(|_| PathError::ConstructionFailed {
                message: format!(
                "Path construction failed - result not within workdir. Final: {:?}, Workdir: {:?}",
                final_path, workdir_canonical
            ),
            })?;

    for component in relative_to_workdir.components() {
        if let std::path::Component::ParentDir = component {
            return Err(PathError::PathTraversal {
                path: ".. components not allowed".to_string(),
            });
        }
    }

    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_normalize_path_str() {
        assert_eq!(normalize_path_str("a//b"), "a/b");
        assert_eq!(normalize_path_str("a\\b"), "a/b");
        assert_eq!(normalize_path_str("a//b//c"), "a/b/c");
        assert_eq!(normalize_path_str("/a/b/"), "a/b");
        assert_eq!(normalize_path_str("a/./b"), "a/./b"); // Doesn't resolve . or ..
    }

    #[test]
    fn test_normalize_path_buf() {
        assert_eq!(normalize_path_buf("a//b"), PathBuf::from("a/b"));
        assert_eq!(normalize_path_buf("a\\b"), PathBuf::from("a/b"));
    }

    #[test]
    fn test_join_and_normalize() {
        assert_eq!(
            join_and_normalize("source/", "/main.rs"),
            PathBuf::from("source/main.rs")
        );
        assert_eq!(
            join_and_normalize("source", "main.rs"),
            PathBuf::from("source/main.rs")
        );
        assert_eq!(
            join_and_normalize("source//", "//main.rs"),
            PathBuf::from("source/main.rs")
        );
        assert_eq!(
            join_and_normalize(PathBuf::from("source/"), PathBuf::from("/main.rs")),
            PathBuf::from("source/main.rs")
        );
    }

    #[test]
    fn test_sanitize_directory_file_path() {
        // Test absolute path conversion - this is the core bug fix
        assert_eq!(sanitize_directory_file_path("/args.js").unwrap(), "args.js");
        assert_eq!(
            sanitize_directory_file_path("/lib/generator.js").unwrap(),
            "lib/generator.js"
        );
        assert_eq!(
            sanitize_directory_file_path("/config/args.js").unwrap(),
            "config/args.js"
        );

        // Test already relative paths (should be unchanged)
        assert_eq!(sanitize_directory_file_path("args.js").unwrap(), "args.js");
        assert_eq!(
            sanitize_directory_file_path("lib/generator.js").unwrap(),
            "lib/generator.js"
        );

        // Test path normalization
        assert_eq!(
            sanitize_directory_file_path("lib//generator.js").unwrap(),
            "lib/generator.js"
        );
        assert_eq!(
            sanitize_directory_file_path("lib\\generator.js").unwrap(),
            "lib/generator.js"
        );

        // Test empty path rejection
        assert!(sanitize_directory_file_path("").is_err());
        assert!(sanitize_directory_file_path("   ").is_err());

        // Test path traversal rejection
        assert!(sanitize_directory_file_path("../etc/passwd").is_err());
        assert!(sanitize_directory_file_path("lib/../../../etc/passwd").is_err());
        assert!(sanitize_directory_file_path("..\\windows\\system32").is_err());
    }

    #[test]
    fn test_sanitize_directory_file_path_security() {
        // Test invalid characters
        assert!(sanitize_directory_file_path("file<script>").is_err());
        assert!(sanitize_directory_file_path("file|pipe").is_err());
        assert!(sanitize_directory_file_path("file?query").is_err());
        assert!(sanitize_directory_file_path("file*glob").is_err());
        assert!(sanitize_directory_file_path("file\"quote").is_err());

        // Test null bytes and control characters
        assert!(sanitize_directory_file_path("file\0null").is_err());
        assert!(sanitize_directory_file_path("file\x01control").is_err());

        // Test Windows reserved names
        assert!(sanitize_directory_file_path("CON").is_err());
        assert!(sanitize_directory_file_path("PRN.txt").is_err());
        assert!(sanitize_directory_file_path("lib/AUX.js").is_err());
        assert!(sanitize_directory_file_path("COM1.exe").is_err());
        assert!(sanitize_directory_file_path("LPT9.log").is_err());

        // Test case-insensitive reserved names
        assert!(sanitize_directory_file_path("con").is_err());
        assert!(sanitize_directory_file_path("Con.txt").is_err());
        assert!(sanitize_directory_file_path("lib/aux.js").is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_sanitize_directory_file_path_windows() {
        // Test Windows drive letter rejection
        assert!(sanitize_directory_file_path("C:\\Windows\\System32").is_err());
        assert!(sanitize_directory_file_path("D:/data/file.txt").is_err());
        assert!(sanitize_directory_file_path("c:\\file.txt").is_err());
    }

    #[test]
    fn test_safe_repository_join() {
        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();

        // Use canonical temp dir for expectations since that's what safe_repository_join returns
        let temp_dir_canonical = temp_dir.path().canonicalize().unwrap();

        // Test normal case - absolute path from directory content
        let result =
            safe_repository_join(temp_dir.path(), "testing/framework", "/args.js").unwrap();
        let expected = temp_dir_canonical.join("testing/framework/args.js");
        assert_eq!(result, expected);

        // Test already relative path
        let result =
            safe_repository_join(temp_dir.path(), "testing/framework", "lib/generator.js").unwrap();
        let expected = temp_dir_canonical.join("testing/framework/lib/generator.js");
        assert_eq!(result, expected);

        // Test nested directory structure
        let result =
            safe_repository_join(temp_dir.path(), "tools/build", "config/webpack.js").unwrap();
        let expected = temp_dir_canonical.join("tools/build/config/webpack.js");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_safe_repository_join_security() {
        let temp_dir = TempDir::new().unwrap();

        // Test path traversal rejection
        assert!(safe_repository_join(temp_dir.path(), "test", "../../../etc/passwd").is_err());
        assert!(
            safe_repository_join(temp_dir.path(), "test", "..\\..\\windows\\system32").is_err()
        );

        // Test invalid characters rejection
        assert!(safe_repository_join(temp_dir.path(), "test", "file<script>").is_err());
        assert!(safe_repository_join(temp_dir.path(), "test", "file|pipe").is_err());

        // Test empty path rejection
        assert!(safe_repository_join(temp_dir.path(), "test", "").is_err());
        assert!(safe_repository_join(temp_dir.path(), "test", "   ").is_err());
    }

    #[test]
    fn test_cli_bug_reproduction() {
        // This test reproduces the exact CLI bug scenario
        let temp_dir = TempDir::new().unwrap();

        // Use canonical path for expectations
        let temp_dir_canonical = temp_dir.path().canonicalize().unwrap();

        // Simulate TypeScript repository structure move:
        // src/testRunner/parallel/args.js -> testing/test-framework/args.js

        // The bug: directory content has "/args.js" (absolute path)
        // Fixed: safe_repository_join sanitizes to "args.js" (relative path)
        let result =
            safe_repository_join(temp_dir.path(), "testing/test-framework", "/args.js").unwrap();
        let expected = temp_dir_canonical.join("testing/test-framework/args.js");
        assert_eq!(result, expected);

        // Verify the result is within the repository (not root filesystem)
        assert!(result.starts_with(&temp_dir_canonical));

        // Most importantly: verify the result is NOT attempting to write to root filesystem
        let result_str = result.to_string_lossy();
        assert!(
            !result_str.starts_with("/args.js"),
            "Should not write to root filesystem!"
        );
        assert!(
            result_str.contains("args.js"),
            "Should contain the filename"
        );
    }
}