#!/usr/bin/python
import socket
import subprocess
import sys
import os
import recon


if len(sys.argv) != 2:
    print "Usage: smtprecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

try:
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting SMTP script scan for {0}\033[1;m'.format(ip_address))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    SMTPSCAN = "nmap -vv -sV -Pn -p 25,465,587 --script-args=unsafe=1 --script=smtp* -oN './results/{0}/{0}_smtp.nmap' -oX './results/{0}/{0}_nmap_scan_smtp.xml' {0}".format(ip_address)
    results = subprocess.check_output(SMTPSCAN, shell=True)
    recon.logparsertxt(results)

    # Test for presence of the VRFY command
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting SMTP Enum on {0}\033[1;m'.format(ip_address))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((ip_address,25))
        banner = s.recv(1024)
        s.send('HELO test@test.org \r\n')
        result = s.recv(1024)
        s.send('VRFY ' + "TEST" + '\r\n')
        result = s.recv(1024)
        if ("not implemented" in result) or ("disallowed" in result):
            s.close()
            print('\033[1;33m[-]  VRFY command not implemented on {0}\033[1;m'.format(ip_address))
        else:
            print('\033[1;33m[+]  \033[1;33mVRFY command is enabled on {0} starting bruteforce\033[1;m'.format(ip_address))
            try:
                names = open('/usr/share/dnsrecon/namelist.txt', 'r')
                for name in names:
                    name = str(name.strip())
                    s.send('VRFY ' + name + '\r\n')
                    result2 = s.recv(1024)
                    if (("250" in result2) or ("252" in result2) and ("Cannot VRFY" not in result2)):
                        print('\033[1;32m[+]  \033[1;37mSMTP VRFY Account found on {0} : {1}\033[1;m'.format(ip_address, name))
                        outfile = "results/{0}/{0}_smtprecon.txt".format(ip_address)
                        f = open(outfile, "w")
                        f.write("[+]  SMTP VRFY Account found on {0} : {1}".format(ip_address, name))
                        f.close()
            except:
                print('\033[1;33m[-]  VRFY command check failed for {0}\033[1;m'.format(ip_address))
            s.close()
            sys.exit()
    except:
        pass
except:
    print('\033[1;31m[-]  SMTP script scan for {0} had some errors.\033[1;m'.format(ip_address))
os.system('stty echo')

