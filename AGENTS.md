# Repository Guidelines

This repo targets Python 3.13 and depends on `tp-connected`. Keep contributions lean, well-tested, and documented.

## Project Structure & Module Organization
- Place application code in `src/` (create if missing) with clear package boundaries; keep CLI helpers in `scripts/`.
- Put tests in `tests/` mirroring the source layout (`tests/<package>/test_<module>.py`).
- Track dependencies in `requirements.txt`; keep virtual-env artifacts out of commits even if a local `venv/` exists for convenience.

## Build, Test, and Development Commands
- Create/refresh the env: `python -m venv venv && source venv/bin/activate`.
- Install deps: `pip install -r requirements.txt`.
- Run tests: `pytest` (add `-q` for quick feedback or `-k <expr>` to focus).
- Lint/format: `python -m pip install black ruff` then `black .` and `ruff check .` (add as pre-commit once stable).

## Coding Style & Naming Conventions
- Follow PEP 8 with 4-space indents; prefer pure functions and small modules.
- Use type hints and short docstrings for non-obvious behavior or public APIs.
- Naming: packages/modules `snake_case`, classes `PascalCase`, functions/vars `snake_case`, constants `UPPER_SNAKE_CASE`.
- Keep functions cohesive; extract helpers instead of long branches, and avoid side effects in import scope.

## Testing Guidelines
- Use `pytest`; name files `test_*.py` and structure tests as arrange/act/assert.
- Prefer fixture reuse over ad-hoc setup; favor deterministic data over randomness.
- Add regression tests before fixes when possible; aim for meaningful coverage on new/changed code paths.
- Run `pytest` locally before pushing; include failure reproduction notes in test names/docstrings when helpful.

## Commit & Pull Request Guidelines
- Write small, focused commits in imperative voice (e.g., `fix: handle empty payload`); keep first line ≤72 chars.
- PRs should describe intent, key changes, and risks; link issues/tasks and note testing performed.
- Include screenshots or CLI transcripts only when output UX changes; update docs or examples alongside behavior changes.
- Ensure lint/tests pass before requesting review; call out follow-ups explicitly instead of deferring silently.

## Security & Configuration Tips
- Do not commit secrets or tokens; load them via environment variables or `.envrc` (kept local).
- Scrub logs/fixtures of sensitive values; prefer configuration files in `config/` with sane defaults and overrides via env vars.

## TP-Link M7000/M7200 Notes
- The client uses AES-CBC and RSA (PKCS1 v1.5) mirroring `tp-link-m7200-api` challenge/login flow; keys/IVs are generated per login.
- `m7200.py` exposes commands for login, status, SMS send/read, network mode, mobile data toggle, reboot, and arbitrary module/action invocations.
- Default modem host is `192.168.0.1` and username `admin`; override via CLI flags or `m7200.ini`.
- Keep traffic on the modem LAN (HTTP only); avoid logging tokens or AES material at info level (use `-v` only for debugging).
