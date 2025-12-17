"""Legacy entrypoint for running the CLI directly from the repo."""

from __future__ import annotations

import os
import sys


def _ensure_src_on_path() -> None:
    repo_root = os.path.dirname(__file__)
    src_path = os.path.join(repo_root, "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)


def main() -> None:
    _ensure_src_on_path()
    from tplink_m7200.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
