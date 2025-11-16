//! Property test generators for path utilities
//!
//! This module provides generators for property-based testing of path operations.
//! Generators are designed to create comprehensive test cases including edge cases
//! and security-relevant scenarios.

use proptest::prelude::*;
use std::path::PathBuf;

/// Generators for path testing scenarios
pub struct PathGenerators;

impl PathGenerators {
    /// Generate valid filename components (no path separators, safe characters)
    pub fn filename_component() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,30}[a-zA-Z0-9_]"
            .prop_filter("Non-empty filename", |s| !s.is_empty() && !s.contains(".."))
    }

    /// Generate file extensions commonly found in Git repositories
    pub fn file_extension() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("rs".to_string()),
            Just("js".to_string()),
            Just("ts".to_string()),
            Just("txt".to_string()),
            Just("md".to_string()),
            Just("json".to_string()),
            Just("toml".to_string()),
            Just("yaml".to_string()),
            Just("py".to_string()),
            Just("go".to_string()),
            Just("java".to_string()),
            Just("c".to_string()),
            Just("cpp".to_string()),
            Just("h".to_string()),
            Just("".to_string()), // Files without extension
        ]
    }

    /// Generate a complete filename with extension
    pub fn filename() -> impl Strategy<Value = String> {
        (Self::filename_component(), Self::file_extension()).prop_map(|(name, ext)| {
            if ext.is_empty() {
                name
            } else {
                format!("{}.{}", name, ext)
            }
        })
    }

    /// Generate directory names
    pub fn directory_name() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_][a-zA-Z0-9_-]{0,20}[a-zA-Z0-9_]".prop_filter("Valid directory name", |s| {
            !s.is_empty() && !s.contains("..")
        })
    }

    /// Generate safe relative paths (no security issues)
    pub fn safe_relative_path() -> impl Strategy<Value = String> {
        prop::collection::vec(Self::directory_name(), 0..=4).prop_flat_map(|dirs| {
            Self::filename().prop_map(move |filename| {
                let mut parts = dirs.clone();
                parts.push(filename);
                parts.join("/")
            })
        })
    }

    /// Generate absolute paths (for conversion testing)
    pub fn absolute_path() -> impl Strategy<Value = String> {
        Self::safe_relative_path().prop_map(|path| format!("/{}", path))
    }

    /// Generate Windows-style paths (for cross-platform testing)
    pub fn windows_path() -> impl Strategy<Value = String> {
        Self::safe_relative_path().prop_map(|path| path.replace('/', "\\"))
    }

    /// Generate paths with double slashes (for normalization testing)
    pub fn path_with_double_slashes() -> impl Strategy<Value = String> {
        Self::safe_relative_path().prop_map(|path| path.replace("/", "//"))
    }

    /// Generate paths with mixed separators (for normalization testing)
    pub fn path_with_mixed_separators() -> impl Strategy<Value = String> {
        prop::collection::vec(Self::directory_name(), 0..=3).prop_flat_map(|dirs| {
            Self::filename().prop_map(move |filename| {
                let mut result = String::new();
                for (i, dir) in dirs.iter().enumerate() {
                    if i > 0 {
                        // Randomly use forward or backward slash
                        if i % 2 == 0 {
                            result.push('/');
                        } else {
                            result.push('\\');
                        }
                    }
                    result.push_str(dir);
                }
                if !dirs.is_empty() {
                    result.push('/');
                }
                result.push_str(&filename);
                result
            })
        })
    }

    /// Generate dangerous paths (for security testing)
    pub fn dangerous_path() -> impl Strategy<Value = String> {
        prop_oneof![
            // Path traversal attempts
            Just("../etc/passwd".to_string()),
            Just("../../windows/system32".to_string()),
            Just("lib/../../../etc/passwd".to_string()),
            Just("..\\..\\windows\\system32".to_string()),
            // Empty and whitespace paths
            Just("".to_string()),
            Just("   ".to_string()),
            Just("\t".to_string()),
            // Paths with null bytes
            Just("file\0null".to_string()),
            Just("path/to\0/file".to_string()),
            // Paths with control characters
            Just("file\x01control".to_string()),
            Just("file\x08backspace".to_string()),
            Just("file\x1Fescape".to_string()),
            // Windows-problematic characters
            Just("file<script>".to_string()),
            Just("file|pipe".to_string()),
            Just("file?query".to_string()),
            Just("file*glob".to_string()),
            Just("file\"quote".to_string()),
            // Windows reserved names
            Just("CON".to_string()),
            Just("PRN".to_string()),
            Just("AUX".to_string()),
            Just("NUL".to_string()),
            Just("COM1".to_string()),
            Just("LPT1".to_string()),
            Just("con.txt".to_string()),
            Just("prn.log".to_string()),
            Just("lib/aux.js".to_string()),
            // Case variations of reserved names
            Just("Con".to_string()),
            Just("con".to_string()),
        ]
    }

    /// Generate Windows drive letter paths (for platform testing)
    #[cfg(windows)]
    pub fn drive_letter_path() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("C:\\Windows\\System32".to_string()),
            Just("D:\\data\\file.txt".to_string()),
            Just("c:\\file.txt".to_string()),
            Just("E:/mixed/separators.txt".to_string()),
        ]
    }

    /// Generate edge case paths that test boundary conditions
    pub fn edge_case_path() -> impl Strategy<Value = String> {
        prop_oneof![
            // Very short paths
            Just("a".to_string()),
            Just("x.rs".to_string()),
            Just("i".to_string()),
            // Very long paths (but still reasonable)
            Just(
                "very/deep/directory/structure/with/many/levels/and/a/very/long/filename.extension"
                    .to_string()
            ),
            // Paths with dots
            Just("file.with.dots.extension".to_string()),
            Just(".hidden".to_string()),
            Just("..hidden".to_string()), // Not traversal, just starts with dots
            Just("file.".to_string()),
            // Paths with special but valid characters
            Just("file-with-dashes.txt".to_string()),
            Just("file_with_underscores.txt".to_string()),
            Just("file with spaces.txt".to_string()),
            // Unicode characters
            Just("файл.txt".to_string()),
            Just("文件.txt".to_string()),
            Just("ファイル.txt".to_string()),
        ]
    }

    /// Generate repository-style directory content paths (like Git extracts)
    pub fn directory_content_path() -> impl Strategy<Value = String> {
        prop_oneof![
            // Paths that would appear in Git directory content
            Self::absolute_path(),
            Self::safe_relative_path(),
            Self::windows_path().prop_map(|p| format!("/{}", p.replace("\\", "/"))),
        ]
    }

    /// Generate path pairs for join operations
    pub fn path_join_pair() -> impl Strategy<Value = (String, String)> {
        (Self::safe_relative_path(), Self::safe_relative_path())
    }

    /// Generate all types of paths for comprehensive testing
    pub fn any_path() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => Self::safe_relative_path(),
            2 => Self::absolute_path(),
            2 => Self::windows_path(),
            2 => Self::path_with_double_slashes(),
            2 => Self::path_with_mixed_separators(),
            1 => Self::edge_case_path(),
            1 => Self::dangerous_path(),
        ]
    }
}

/// Test case generators for specific scenarios
pub struct ScenarioGenerators;

impl ScenarioGenerators {
    /// Generate a directory content entry as Git would extract it
    pub fn directory_content_entry() -> impl Strategy<Value = (String, String)> {
        (
            PathGenerators::directory_content_path(),
            // Simple content for the file
            "[a-zA-Z0-9 ]{0,100}".prop_map(|s| s.trim().to_string()),
        )
    }

    /// Generate a repository join scenario
    pub fn repository_join_scenario() -> impl Strategy<Value = (PathBuf, String, String)> {
        (
            // Workdir (absolute path)
            Just(std::env::temp_dir()).prop_map(|mut p| {
                p.push("test-repo");
                p
            }),
            // Target path (relative)
            PathGenerators::safe_relative_path(),
            // File path from directory content (could be absolute)
            PathGenerators::directory_content_path(),
        )
    }

    /// Generate normalization test cases
    pub fn normalization_scenario() -> impl Strategy<Value = (String, String)> {
        PathGenerators::path_with_double_slashes().prop_map(|path| {
            let normalized = path.replace("//", "/");
            (path, normalized)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn path_generators_produce_valid_output(
            safe_path in PathGenerators::safe_relative_path()
        ) {
            // Safe paths should not be empty and not contain dangerous patterns
            prop_assert!(!safe_path.is_empty());
            prop_assert!(!safe_path.contains(".."));
            prop_assert!(!safe_path.contains('\0'));
        }

        #[test]
        fn dangerous_paths_contain_security_issues(
            dangerous_path in PathGenerators::dangerous_path()
        ) {
            // Dangerous paths should trigger our validation logic
            // Check for various security issues
            let is_dangerous = dangerous_path.is_empty()
                || dangerous_path.trim().is_empty()
                || dangerous_path.contains("..")
                || dangerous_path.contains('\0')
                || dangerous_path.chars().any(|c| c.is_control())
                || ['<', '>', '|', '?', '*', '"'].iter().any(|&c| dangerous_path.contains(c))
                || ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
                    "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
                    "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"].iter().any(|&reserved| {
                    // Check component matches exactly (with or without extension)
                    dangerous_path.split('/').chain(dangerous_path.split('\\'))
                        .any(|component| {
                            let base_name = component.split('.').next().unwrap_or("");
                            base_name.to_uppercase() == reserved
                        })
                });

            prop_assert!(is_dangerous, "Path should be considered dangerous: {}", dangerous_path);
        }

        #[test]
        fn generators_dont_panic(
            _any_path in PathGenerators::any_path()
        ) {
            // This test just ensures our generators don't panic
            // The actual path validation is tested elsewhere
        }
    }
}