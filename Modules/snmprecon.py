#!/usr/bin/env python
import subprocess
import sys
import os
import recon

if len(sys.argv) != 2:
    print "Usage: snmprecon.py <ip address>"
    sys.exit(0)

snmpdetect = 0
ip_address = sys.argv[1]

try:
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting SNMP scan for {0}\033[1;m'.format(ip_address))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    ONESIXONESCAN = "onesixtyone %s" % (ip_address)
    results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()


    if results != "":
        if "Windows" in results:
            results = results.split("Software: ")[1]
            snmpdetect = 1
        elif "Linux" in results:
            results = results.split("[public] ")[1]
            snmpdetect = 1
        if snmpdetect == 1:
            print('\033[1;32m[+]  SNMP running on {0}; OS Detect: {1}\033[1;m'.format(ip_address, results))
            SNMPWALK = "snmpwalk -c public -v1 {0} 1 >> ./results/{0}/{0}_snmp.txt".format(ip_address)
            results = subprocess.check_output(SNMPWALK, shell=True)
            SNMPCHECK = "snmp-check -t {0} >> ./results/{0}/{0}_snmp.txt".format(ip_address)
            results = subprocess.check_output(SNMPCHECK, shell=True)

    NMAPSCAN = "nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-* {0}".format(ip_address)
    results = subprocess.check_output(NMAPSCAN, shell=True)
    recon.logparsertxt(results)
    outfile = "results/{0}/{0}_snmprecon.txt".format(ip_address)
    f = open(outfile, "w")
    f.write(results)
    f.close()
except:
    print('\033[1;31m[-]  SNMP script scan for {0} had some errors.\033[1;m'.format(ip_address))
os.system('stty echo')
