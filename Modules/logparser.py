#!/usr/bin/python
import sys

if len(sys.argv) != 2:
    print "Usage: logparser.py <textfile>"
    sys.exit(0)

ip = sys.argv[1]
protocol = sys.argv[2]

def logparsertxt(results):
    for line in results:
        if ("|" in line) or (" . " in line):
                print '\033[1;32m[+]  ' + line + '\033[1;m'
    return