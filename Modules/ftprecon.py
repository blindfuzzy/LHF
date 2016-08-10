#!/usr/bin/env python
import subprocess
import sys
import recon

if len(sys.argv) != 3:
    print "Usage: ftprecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()
print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
print('\033[1;37m[-]  |     Starting FTP script scan for {0}:{1} - [This can take a long time]\033[1;m'.format(ip_address, port))
print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"

if not recon.checknmaprunmod(ip_address, "_ftp{0}.nmap".format(port)):
    FTPSCAN = "nmap -sV -Pn -vv -p {0} --script=ftp-* -oN './results/{1}/{1}_ftp{0}.nmap' {1}".format(port, ip_address)
    results = subprocess.check_output(FTPSCAN, shell=True)
    recon.logparsertxt(results)
else:
    print('\033[1;33m[+]  {0} already scanned for FTP port {1}...\033[1;m'.format(ip_address, port))
    results = open("./results/{0}/{0}_ftp{1}.nmap".format(ip_address, port), "r")
    recon.logparserfile(results)

# ==> Hydrascan disabled due to there is a brutescan allready in the nmap modules. if wanting to brute with own list it can be disabled and user and passwordlist added to wordlists

# print "INFO: Performing hydra ftp scan against {0}".format(ip_address)
# HYDRA = "hydra -L ./wordlists/ftpusers -P ./wordlists/ftppasswords -f -o ./results/{0}/{0}_ftphydra.txt -u {0} -s {1} ftp".format(ip_address, port)
# results = subprocess.check_output(HYDRA, shell=True)
# resultarr = results.split("\n")
# for result in resultarr:
#     if "login:" in result:
#         print "[*] Valid ftp credentials found: {0}".format(result)
#         outfile = "results/{0}/{0}_ftprecon.txt".format(ip_address)
#         f = open(outfile, "w")
#         f.write("[*] Valid ftp credentials found: {0}".format(result))
#         f.close


