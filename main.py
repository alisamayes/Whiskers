#Structure

#Main start interface
#Description of functions to user

# Gen logs
# Parse logs

import sys
from whiskers import Whiskers


whiskers = Whiskers(sys.argv[1:])
whiskers.await_input()