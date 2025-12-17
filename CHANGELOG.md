# Changelog

All notable changes to this project are documented in this file.
Versions use date-based versioning: YYYY.MM.DD.

## 2025.12.17
- Added session cache support with export/import and validation to reuse logins.
- Added `session_file` support in `m7200.ini` and CLI caching flag.
- Ignored `m7200.session.json` from version control.
- Moved decrypted response logs to debug level.
- Removed unused `tp-connected` dependency.
- Replaced deprecated `datetime.utcnow()` usage with `datetime.now(UTC)`.
- Added `pyproject.toml` and migrated code into `src/` with a `m7200` console script.
