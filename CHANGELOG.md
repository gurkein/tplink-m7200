# Changelog

All notable changes to this project are documented in this file.
Versions use date-based versioning: YYYYMMDD.

## 20251219
- Added client helpers for SMS, status, network mode, mobile data, IP, and quota.
- Added configurable request timeout (config/CLI) for HTTP calls; default 10s.

## 20251218
- Set Python requirement to 3.11+ with updated classifiers.
- Added PyPI metadata and a publish workflow triggered on tags.
- Added MIT license file and metadata.

## 20251217
- Added session cache support with export/import and validation to reuse logins.
- Added `session_file` support in `m7200.ini` and CLI caching flag.
- Ignored `m7200.session.json` from version control.
- Moved decrypted response logs to debug level.
- Removed unused `tp-connected` dependency.
- Replaced deprecated `datetime.utcnow()` usage with `datetime.now(UTC)`.
- Added `pyproject.toml` and migrated code into `src/` with a `m7200` console script.
