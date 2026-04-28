"""Module entrypoint for `python -m Whiskers.cli.main`."""

from __future__ import annotations

import sys

from whiskers import Whiskers


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    whiskers = Whiskers(args)
    whiskers.await_input()


if __name__ == "__main__":
    main()
