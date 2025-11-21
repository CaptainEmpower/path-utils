//! Property tests for path-utils
//!
//! These tests verify important invariants and properties of path operations
//! across a wide range of inputs including edge cases and malicious inputs.

use path_utils::*;
use proptest::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

// Define local path generators for property testing
mod test_generators {
    use proptest::prelude::*;

    /// Generators for path testing scenarios
    pub struct PathGenerators;

    impl PathGenerators {
        /// Generate safe relative paths (no security issues)
        pub fn safe_relative_path() -> impl Strategy<Value = String> {
            "[a-zA-Z0-9_][a-zA-Z0-9_/-]{0,30}[a-zA-Z0-9_]".prop_filter("Safe relative path", |s| {
                !s.is_empty() && !s.contains("..") && !s.contains('\0') && !s.starts_with('/')
            })
        }

        /// Generate absolute paths (for conversion testing)
        pub fn absolute_path() -> impl Strategy<Value = String> {
            Self::safe_relative_path().prop_map(|path| format!("/{}", path))
        }

        /// Generate paths with double slashes (for normalization testing)
        pub fn path_with_double_slashes() -> impl Strategy<Value = String> {
            Self::safe_relative_path().prop_map(|path| path.replace("/", "//"))
        }

        /// Generate dangerous paths (for security testing)
        pub fn dangerous_path() -> impl Strategy<Value = String> {
            prop_oneof![
                // Path traversal attempts
                Just("../etc/passwd".to_string()),
                Just("../../windows/system32".to_string()),
                Just("lib/../../../etc/passwd".to_string()),
                // Empty and whitespace paths
                Just("".to_string()),
                Just("   ".to_string()),
                // Paths with null bytes
                Just("file\0null".to_string()),
                // Windows-problematic characters
                Just("file<script>".to_string()),
                Just("file|pipe".to_string()),
                // Windows reserved names
                Just("CON".to_string()),
                Just("PRN".to_string()),
                Just("AUX".to_string()),
            ]
        }

        /// Generate any type of path
        pub fn any_path() -> impl Strategy<Value = String> {
            prop_oneof![
                3 => Self::safe_relative_path(),
                2 => Self::absolute_path(),
                2 => Self::path_with_double_slashes(),
                1 => Self::dangerous_path(),
            ]
        }

        /// Generate directory content paths (like Git extracts)
        pub fn directory_content_path() -> impl Strategy<Value = String> {
            prop_oneof![Self::absolute_path(), Self::safe_relative_path(),]
        }
    }
}

use test_generators::PathGenerators;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: Path normalization is idempotent
    /// normalize(normalize(path)) == normalize(path)
    #[test]
    fn normalization_is_idempotent(
        path in PathGenerators::any_path()
    ) {
        let normalized_once = normalize_path_str(&path);
        let normalized_twice = normalize_path_str(&normalized_once);

        prop_assert_eq!(
            normalized_once,
            normalized_twice,
            "Normalization should be idempotent"
        );
    }

    /// Property: Normalized paths never contain double slashes
    #[test]
    fn normalized_paths_have_no_double_slashes(
        path in PathGenerators::any_path()
    ) {
        let normalized = normalize_path_str(&path);
        prop_assert!(
            !normalized.contains("//"),
            "Normalized path should not contain double slashes: {}",
            normalized
        );
    }

    /// Property: Normalized paths never contain backslashes (cross-platform consistency)
    #[test]
    fn normalized_paths_have_no_backslashes(
        path in PathGenerators::any_path()
    ) {
        let normalized = normalize_path_str(&path);
        prop_assert!(
            !normalized.contains('\\'),
            "Normalized path should not contain backslashes: {}",
            normalized
        );
    }

    /// Property: Path join and normalize is associative for safe paths
    /// join(a, join(b, c)) == join(join(a, b), c) after normalization
    #[test]
    fn path_joining_is_associative(
        a in PathGenerators::safe_relative_path(),
        b in PathGenerators::safe_relative_path(),
        c in PathGenerators::safe_relative_path()
    ) {
        let path_a = PathBuf::from(a);
        let path_b = PathBuf::from(b);
        let path_c = PathBuf::from(c);

        let left_associative = join_and_normalize(&path_a, &join_and_normalize(&path_b, &path_c));
        let right_associative = join_and_normalize(&join_and_normalize(&path_a, &path_b), &path_c);

        prop_assert_eq!(
            left_associative,
            right_associative,
            "Path joining should be associative"
        );
    }

    /// Property: Safe relative paths are accepted by sanitization
    #[test]
    fn safe_paths_pass_sanitization(
        path in PathGenerators::safe_relative_path()
    ) {
        prop_assume!(!path.is_empty());
        prop_assume!(!path.trim().is_empty());

        let result = sanitize_directory_file_path(&path);
        prop_assert!(
            result.is_ok(),
            "Safe path should pass sanitization: {} -> {:?}",
            path,
            result
        );
    }

    /// Property: Dangerous paths are rejected by sanitization
    #[test]
    fn dangerous_paths_fail_sanitization(
        path in PathGenerators::dangerous_path()
    ) {
        let result = sanitize_directory_file_path(&path);
        prop_assert!(
            result.is_err(),
            "Dangerous path should be rejected: {}",
            path
        );
    }

    /// Property: Absolute paths are converted to relative paths
    #[test]
    fn absolute_paths_become_relative(
        path in PathGenerators::safe_relative_path().prop_map(|p| format!("/{}", p))
    ) {
        prop_assume!(!path[1..].trim().is_empty()); // Skip the leading slash, ensure content exists

        let result = sanitize_directory_file_path(&path);
        if let Ok(sanitized) = result {
            prop_assert!(
                !sanitized.starts_with('/'),
                "Sanitized path should not start with slash: {} -> {}",
                path,
                sanitized
            );

            // Should be the same as the original without leading slash, but also normalized
            let expected = normalize_path_str(&path[1..]);
            prop_assert_eq!(
                sanitized,
                expected,
                "Sanitized path should match normalized path without leading slash"
            );
        }
    }

    /// Property: Sanitization preserves valid content
    #[test]
    fn sanitization_preserves_valid_content(
        path in PathGenerators::safe_relative_path()
    ) {
        prop_assume!(!path.is_empty());
        prop_assume!(!path.trim().is_empty());

        let result = sanitize_directory_file_path(&path);
        if let Ok(sanitized) = result {
            // Extract filenames to compare
            let original_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            let sanitized_parts: Vec<&str> = sanitized.split('/').filter(|s| !s.is_empty()).collect();

            prop_assert_eq!(
                original_parts,
                sanitized_parts,
                "Sanitization should preserve path components for safe paths"
            );
        }
    }

    /// Property: Repository joining produces paths within the repository
    #[test]
    fn repository_joining_contains_paths(
        target_rel in PathGenerators::safe_relative_path(),
        file_path in PathGenerators::directory_content_path()
    ) {
        let temp_dir = TempDir::new().unwrap();
        let workdir = temp_dir.path();

        let result = safe_repository_join(workdir, &target_rel, &file_path);
        if let Ok(joined_path) = result {
            let workdir_canonical = workdir.canonicalize().unwrap();
            prop_assert!(
                joined_path.starts_with(&workdir_canonical),
                "Joined path should be within repository: {:?} should start with {:?}",
                joined_path,
                workdir_canonical
            );
        }
    }

    /// Property: Path validation is consistent with is_safe_path
    #[test]
    fn validation_consistency(
        path in PathGenerators::any_path()
    ) {
        let is_safe = is_safe_path(&path);
        let validation_result = validate_path(&path);

        prop_assert_eq!(
            is_safe,
            validation_result.is_ok(),
            "is_safe_path and validate_path should be consistent for: {}",
            path
        );
    }

    /// Property: Windows reserved names are always rejected
    #[test]
    fn windows_reserved_names_rejected(
        reserved_name in prop_oneof![
            Just("CON".to_string()),
            Just("PRN".to_string()),
            Just("AUX".to_string()),
            Just("NUL".to_string()),
            Just("COM1".to_string()),
            Just("LPT1".to_string()),
            Just("con".to_string()),
            Just("prn".to_string()),
            Just("aux".to_string()),
        ]
    ) {
        let result = sanitize_directory_file_path(&reserved_name);
        prop_assert!(
            result.is_err(),
            "Windows reserved name should be rejected: {}",
            reserved_name
        );

        prop_assert!(
            !is_safe_path(&reserved_name),
            "Windows reserved name should not be considered safe: {}",
            reserved_name
        );
    }

    /// Property: Paths with null bytes are always rejected
    #[test]
    fn null_bytes_rejected(
        base_path in PathGenerators::safe_relative_path(),
        null_position in 0usize..10usize
    ) {
        let mut path_with_null = base_path.clone();
        if null_position < path_with_null.len() {
            path_with_null.insert(null_position, '\0');
        } else {
            path_with_null.push('\0');
        }

        let result = sanitize_directory_file_path(&path_with_null);
        prop_assert!(
            result.is_err(),
            "Path with null byte should be rejected: {:?}",
            path_with_null
        );

        prop_assert!(
            !is_safe_path(&path_with_null),
            "Path with null byte should not be considered safe: {:?}",
            path_with_null
        );
    }

    /// Property: Path traversal attempts are always rejected
    #[test]
    fn path_traversal_rejected(
        base_path in PathGenerators::safe_relative_path(),
        traversal_pattern in prop_oneof![
            Just("../".to_string()),
            Just("..\\".to_string()),
            Just("/..".to_string()),
            Just("\\..".to_string()),
        ]
    ) {
        let traversal_path = format!("{}{}{}", traversal_pattern, base_path, traversal_pattern);

        let result = sanitize_directory_file_path(&traversal_path);
        prop_assert!(
            result.is_err(),
            "Path traversal should be rejected: {}",
            traversal_path
        );

        prop_assert!(
            !is_safe_path(&traversal_path),
            "Path traversal should not be considered safe: {}",
            traversal_path
        );
    }

    /// Property: Join and normalize operations never introduce security issues
    #[test]
    fn join_operations_are_safe(
        base in PathGenerators::safe_relative_path(),
        path in PathGenerators::safe_relative_path()
    ) {
        let joined = join_and_normalize(&base, &path);
        let joined_str = joined.to_string_lossy().to_string();

        // The result should still be safe
        prop_assert!(
            is_safe_path(&joined_str),
            "Joining safe paths should produce safe result: {} + {} = {}",
            base,
            path,
            joined_str
        );

        // Should not contain dangerous patterns
        prop_assert!(
            !joined_str.contains(".."),
            "Joined path should not contain path traversal: {}",
            joined_str
        );

        prop_assert!(
            !joined_str.contains("//"),
            "Joined path should not contain double slashes: {}",
            joined_str
        );
    }
}

/// Performance property tests
mod performance_properties {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property: Normalization performance is reasonable
        #[test]
        fn normalization_performance(
            path in PathGenerators::any_path()
        ) {
            let start = std::time::Instant::now();
            let _result = normalize_path_str(&path);
            let duration = start.elapsed();

            prop_assert!(
                duration < std::time::Duration::from_millis(10),
                "Normalization should complete quickly for path: {} (took {:?})",
                path,
                duration
            );
        }

        /// Property: Sanitization performance is reasonable
        #[test]
        fn sanitization_performance(
            path in PathGenerators::any_path()
        ) {
            let start = std::time::Instant::now();
            let _result = sanitize_directory_file_path(&path);
            let duration = start.elapsed();

            prop_assert!(
                duration < std::time::Duration::from_millis(50),
                "Sanitization should complete quickly for path: {} (took {:?})",
                path,
                duration
            );
        }
    }
}

/// Edge case property tests
mod edge_cases {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// Property: Empty components are handled correctly
        #[test]
        fn empty_components_handled(
            parts in prop::collection::vec("[a-zA-Z0-9_]{1,10}", 1..=5)
        ) {
            // Create path with some empty components
            let path_with_empties = parts.join("//");
            let normalized = normalize_path_str(&path_with_empties);
            let expected = parts.join("/");

            prop_assert_eq!(
                normalized,
                expected,
                "Empty components should be removed: {} -> {}",
                path_with_empties,
                "expected path"
            );
        }

        /// Property: Very long paths are handled correctly
        #[test]
        fn long_paths_handled(
            component in "[a-zA-Z0-9_]{1,20}",
            depth in 1usize..50usize
        ) {
            let long_path = (0..depth)
                .map(|i| format!("{}_{}", component, i))
                .collect::<Vec<_>>()
                .join("/");

            // Should not panic and should normalize correctly
            let normalized = normalize_path_str(&long_path);
            prop_assert!(
                !normalized.contains("//"),
                "Long path should normalize correctly: {}",
                normalized
            );

            // If it's a safe path, sanitization should work
            if is_safe_path(&long_path) {
                let result = sanitize_directory_file_path(&long_path);
                prop_assert!(
                    result.is_ok(),
                    "Long safe path should sanitize correctly: {}",
                    long_path
                );
            }
        }
    }
}