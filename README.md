# path-utils

[![Crates.io](https://img.shields.io/crates/v/path-utils)](https://crates.io/crates/path-utils)
[![Documentation](https://docs.rs/path-utils/badge.svg)](https://docs.rs/path-utils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Secure, cross-platform path normalization and validation utilities for Rust.

Originally developed for [git-mvh](https://github.com/CaptainEmpower/git-mvh) but designed to be useful for any application that needs robust path handling with security as a primary concern.

## Features

- **🔒 Security-First**: Path traversal attack prevention, sanitization, and validation
- **🌍 Cross-Platform**: Consistent behavior on Windows, macOS, and Linux
- **⚡ Performance**: Minimal dependencies and optimized for common use cases
- **🛡️ Memory Safe**: Built with Rust's memory safety guarantees
- **✅ Well Tested**: Comprehensive test suite including edge cases and security scenarios

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
path-utils = "0.1"
```

## Usage Examples

### Basic Path Normalization

```rust
use path_utils::{normalize_path_str, join_and_normalize};
use std::path::PathBuf;

// Normalize path separators and remove double slashes
assert_eq!(normalize_path_str("a//b\\c"), "a/b/c");

// Join paths safely with normalization
let result = join_and_normalize("source/", "/main.rs");
assert_eq!(result, PathBuf::from("source/main.rs"));
```

### Security-Focused Path Sanitization

```rust
use path_utils::{sanitize_directory_file_path, safe_repository_join};
use std::path::Path;

// Convert absolute paths to relative (useful for directory content parsing)
let sanitized = sanitize_directory_file_path("/args.js")?;
assert_eq!(sanitized, "args.js");

// Safely join repository paths with validation
let temp_dir = std::env::temp_dir();
let safe_path = safe_repository_join(&temp_dir, "project", "/config.js")?;
// Result: {temp_dir}/project/config.js (safely contained!)
```

### Path Validation

```rust
use path_utils::{is_safe_path, validate_path};

// Quick safety check
assert!(is_safe_path("safe/path/file.txt"));
assert!(!is_safe_path("../etc/passwd"));

// Detailed validation with error information
match validate_path("../dangerous/path") {
    Ok(()) => println!("Path is safe"),
    Err(e) => println!("Path validation failed: {}", e),
}
```

## Security Features

### Path Traversal Prevention

```rust
use path_utils::sanitize_directory_file_path;

// These will return errors due to security violations
assert!(sanitize_directory_file_path("../etc/passwd").is_err());
assert!(sanitize_directory_file_path("dir/../../../root").is_err());
```

### Windows Compatibility & Reserved Names

```rust
use path_utils::sanitize_directory_file_path;

// Prevents Windows reserved filenames
assert!(sanitize_directory_file_path("CON").is_err());
assert!(sanitize_directory_file_path("PRN.txt").is_err());
assert!(sanitize_directory_file_path("AUX.log").is_err());

// Rejects problematic characters
assert!(sanitize_directory_file_path("file<script>").is_err());
assert!(sanitize_directory_file_path("file|pipe").is_err());
```

### Null Byte & Control Character Protection

```rust
use path_utils::sanitize_directory_file_path;

// Prevents null byte injection and control characters
assert!(sanitize_directory_file_path("file\0null").is_err());
assert!(sanitize_directory_file_path("file\x01control").is_err());
```

## API Reference

### Core Functions

| Function | Description | Use Case |
|----------|-------------|----------|
| `normalize_path_str(path)` | Normalize path string | Cross-platform path cleanup |
| `normalize_path_buf(path)` | Normalize PathBuf | Type-safe path normalization |
| `join_and_normalize(base, path)` | Join and normalize paths | Safe path construction |
| `sanitize_directory_file_path(path)` | Sanitize directory content paths | Security-focused path cleaning |
| `safe_repository_join(workdir, target, file)` | Safe repository path joining | Repository file operations |
| `is_safe_path(path)` | Quick safety check | Fast validation |
| `validate_path(path)` | Detailed validation | Error diagnostics |

### Error Handling

The crate uses a comprehensive `PathError` enum for detailed error reporting:

```rust
use path_utils::{PathError, sanitize_directory_file_path};

match sanitize_directory_file_path("../dangerous") {
    Ok(safe_path) => println!("Safe path: {}", safe_path),
    Err(PathError::PathTraversal { path }) => println!("Path traversal in: {}", path),
    Err(PathError::EmptyPath) => println!("Empty path provided"),
    Err(PathError::InvalidCharacters { path }) => println!("Invalid chars in: {}", path),
    Err(e) => println!("Other error: {}", e),
}
```

## Real-World Use Case: Git Operations

This crate was originally developed to solve a critical security bug in git-mvh where directory content parsing extracted absolute paths (`/args.js`) instead of relative paths (`args.js`), causing "Read-only file system" errors and potential security issues.

```rust
use path_utils::safe_repository_join;
use std::path::Path;

// Safe handling of paths from Git directory content
let workdir = Path::new("/repo");
let target = Path::new("testing/framework");
let file_from_git = "/args.js";  // Absolute path from Git content

// This safely converts to: /repo/testing/framework/args.js
let safe_path = safe_repository_join(workdir, target, file_from_git)?;
```

## Testing

The crate includes comprehensive tests for:
- Cross-platform compatibility
- Security boundary enforcement
- Edge case handling
- Performance characteristics

```bash
cargo test -p path-utils
```

## Minimum Supported Rust Version (MSRV)

This crate supports Rust 1.70.0 and later.

## Contributing

Contributions are welcome! Please see the main [git-mvh repository](https://github.com/CaptainEmpower/git-mvh) for contribution guidelines.

## License

Licensed under the MIT License. See [LICENSE](../../LICENSE) for details.

## Related Projects

- [git-mvh](https://crates.io/crates/git-mvh) - Move files between Git repositories while preserving history
- [normpath](https://crates.io/crates/normpath) - Path normalization (without security focus)
- [path-clean](https://crates.io/crates/path-clean) - Path cleaning utilities

## Security

If you discover a security vulnerability, please see the [Security Policy](../../SECURITY.md) in the main repository.