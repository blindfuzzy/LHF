#!/usr/bin/python
import subprocess
import sys
import os
import recon

if len(sys.argv) != 2:
    print "Usage: smbrecon.py <ip address>"
    sys.exit(0)

ip = sys.argv[1]
recon.checkpath("./results/" + ip)
try:
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting SMB script scan for {0}\033[1;m'.format(ip))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    VULNSCAN = "nmap -sV -Pn -vv -p445,139 --script=smb-vuln* --script-args=unsafe=1 -oN './results/{0}/{0}_smb.nmap' {0}".format(ip)
    scanresults = subprocess.check_output(VULNSCAN, shell=True)
    recon.logparsertxt(scanresults)

    NBTSCAN = "./Modules/samrdump.py {0!s}".format((ip))
    nbtresults = subprocess.check_output(NBTSCAN, shell=True)
    if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
        print('\033[1;33m[+]  \033[1;33mSAMRDUMP has connected to {0} if there are results displaying them below\033[1;m'.format(ip))
        lines = nbtresults.split("\n")
        for line in lines:
            if ("Found" in line) or (" . " in line):
                print '\033[1;32m[+]  ' + line + '\033[1;m'
    E4L = "enum4linux {0}".format(ip)
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting ENUM4LINUX for {0}\033[1;m'.format(ip))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    e4lresults = subprocess.check_output(E4L, shell=True)
    recon.logparserall(e4lresults)
except:
    print('\033[1;31m[-]  SMB script scan for {0} had some errors.\033[1;m'.format(ip))
os.system('stty echo')