"""Application entrypoint for running Whiskers from the command line."""

import sys

from whiskers import Whiskers


def main() -> None:
    """Start the Whiskers CLI application.

    Args:
        None

    Returns:
        None
    """
    whiskers = Whiskers(sys.argv[1:])
    whiskers.await_input()


if __name__ == "__main__":
    main()
