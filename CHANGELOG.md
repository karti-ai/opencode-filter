# Changelog

## [2.0.0] - 2025-04-10

### Added
- 230 secret detection patterns across 8 categories
- Native OpenCode TUI integration with visual feedback
- Toast notifications when secrets are filtered
- Status bar indicator showing filter count
- Command palette integration (/filter commands)
- Filter status and audit log panels
- Interactive configuration wizard (`npx opencode-filter init`)
- Comprehensive audit logging system
- Real-world secret corpus (205 test examples)
- Performance benchmarking suite
- Plugin manifest for OpenCode marketplace

### Changed
- Improved config loading with better error handling
- Enhanced pattern matching accuracy to 95.12%
- Updated to dual plugin architecture (server + TUI)

### Fixed
- Config test failures (10 edge cases)
- Path resolution in test environments

## [1.0.0] - 2024-01-01

### Added
- Initial release with core filtering functionality
- 20 built-in secret patterns
- Basic OpenCode plugin hooks
- Session management with LRU eviction
- HMAC-SHA256 placeholder generation
