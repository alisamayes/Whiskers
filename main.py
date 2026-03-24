#Structure

#Main start interface
#Description of functions to user

# Gen logs
# Parse logs

import sys
from whiskers import Whiskers
from GUI.main_window import ApplicationWindow


whiskers = Whiskers(sys.argv[1:])
whiskers.await_input()
#app = ApplicationWindow()
#app.show()