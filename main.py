#Structure

#Main start interface
#Description of functions to user

# Gen logs
# Parse logs

import sys
from whiskers import Whiskers


def main() -> None:
    whiskers = Whiskers(sys.argv[1:])
    whiskers.await_input()


if __name__ == "__main__":
    main()