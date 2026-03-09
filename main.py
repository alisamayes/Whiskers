#Structure

#Main start interface
#Description of functions to user

# Gen logs
# Parse logs

import sys
from parser.log_parser import parse_logs
from analysis.threat_detection import *
from simulator.log_simulator import generate_logs

mode = "normal"
if len(sys.argv) > 1:
    for arg in sys.argv[1:]:
        if arg in ("-h", "--help"):
            print("Usage: python main.py [options]")
            print("Options:")
            print("  -v, --verbose   Enable verbose output")
            print("  -h, --help      Show this help message")
            sys.exit(0)

        elif arg in ("-v", "--verbose"):
            mode = "verbose"
        
        elif arg in ("-g", "--generate"):
            print("Generating logs...")
            generate_logs()
        
        else:
            print("Unknown argument:", arg, " use -v or --verbose for verbose mode")


df = parse_logs("data/access.log")
if mode == "verbose":
    print("Loaded logs:", len(df))

brute = detect_bruteforce(df)

if mode == "verbose":
    for (ip, time), count in brute.items():
        print("⚠ Brute force detected:", ip, time, count)
else:
    print("Brute force attempts detected:", len(brute))

scan = detect_scanning(df)

if mode == "verbose":
    for ip, count in scan.items():
        print("⚠ Directory scan detected:", ip, count)
else:
    print("Directory scans detected:", len(scan))

flood = detect_request_flood(df)

if mode == "verbose":
    for ip, time, count in flood:
        print("⚠ Request flood detected:", ip, time, count)
else:
    print("Request floods detected:", len(flood))