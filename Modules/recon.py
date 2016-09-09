import errno
import multiprocessing
import multiprocessing.pool
import os
import re
import subprocess
import gzip
import sys
import psutil
from selenium import webdriver
from IPy import IP
from socket import gethostbyname

def bootstrap():
    os.system('cls' if os.name == 'nt' else 'clear')
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print '\033[1;37m[-]  ::::::::::::: ########:: ########:: ######::: #######:: ##::: ##::::::::::::: \033[1;m'
    print '\033[1;37m[-]  ::::::::::::: ##.... ##: ##.....:: ##... ##: ##.... ##: ###:: ##::::::::::::: \033[1;m'
    print '\033[1;37m[-]  ::::::::::::: ##:::: ##: ##::::::: ##:::..:: ##:::: ##: ####: ##::::::::::::: \033[1;m'
    print '\033[1;37m[-]  ::::::::::::: ########:: ######::: ##::::::: ##:::: ##: ## ## ##::::::::::::: \033[1;m'
    print '\033[1;37m[-]  ::::::::::::: ##.. ##::: ##...:::: ##::::::: ##:::: ##: ##. ####::::::::::::: \033[1;m'
    print '\033[1;37m[-]  ::::::::::::: ##::. ##:: ##::::::: ##::: ##: ##:::: ##: ##:. ###::::::::::::: \033[1;m'
    print '\033[1;37m[-]  ::::::::::::: ##:::. ##: ########:. ######::. #######:: ##::. ##::::::::::::: \033[1;m'
    print '\033[1;37m[-]  :::::::::::::..:::::..::........:::......::::.......:::..::::..::::::::: 0x90 \033[1;m'
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"

def killrecon():
    print '\033[1;31m[-]  Recon is ending: Killing all Processes!\033[1;m'
    PROCNAME = ("python", "nmap", "dirb", "hydra")
    for proc in psutil.process_iter():
        if proc.name() in PROCNAME:
            proc.kill()
    os.system('stty echo')
    exit()

def finnished():
    os.system('stty echo')
    print('\033[1;33m[+]  Recon has finished!\033[1;m')

def startrecon():
    # See if there is a target list in the file ips
    with open("./ips") as f:
        print('\033[1;33m[+]  Found IP list, using as input\033[1;m')
        ips = f.readlines()

        for ip in ips:
            scanner(ip.strip('\n\r'), 'TCP')
            scanner(ip.strip('\n\r'), 'UDP')

def checkpreq():
    # Check if root
    if os.getuid() == 0:
        print('\033[1;33m[+]  Checking permissions\033[1;m')
    else:
        sys.exit("I cannot run as a mortal. Sorry.")

    if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
        print('\033[1;33m[+]  Rockyou wordlist present\033[1;m')
    else:
        print('\033[1;31m[-]  Rockyou wordlist is missing trying to decompress...\033[1;m')
        try:
            inFile = gzip.GzipFile("/usr/share/wordlists/rockyou.txt.gz", "rb")
            s = inFile.read()
            inFile.close()
            outFile = file("/usr/share/wordlists/rockyou.txt", "wb")
            outFile.write(s)
            outFile.close()
        except:
            pass
        if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
            print('\033[1;32m[+]  Rockyou wordlist is decompressed!\033[1;m')
        else:
            print('\033[1;31m[-]  Decompression of rockyou.txt failed!\033[1;m')


def checkpath(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise


def checknmaprun(ip_address, name):
    if os.path.isfile("./results/{0}/{0}{1}".format(ip_address, name)):
        with open("./results/{0}/{0}{1}".format(ip_address, name)) as f:
            for line in f:
                if 'exit="success"' in line:
                    return True
                if not line:
                    return False
    else:
        return False

def checknmaprunmod(ip_address, name):
    if os.path.isfile("./results/{0}/{0}{1}".format(ip_address, name)):
        with open("./results/{0}/{0}{1}".format(ip_address, name)) as f:
            for line in f:
                if 'Nmap done' in line:
                    return True
                if not line:
                    return False
    else:
        return False

def multProc(targetin, scanip, port):
    jobs = []
    try:
        p = multiprocessing.Process(target=targetin, args=(scanip, port))
        jobs.append(p)
        p.start()
        p.join()
        return
    except:
        pass


def getIp():
    """ Defines the ip range to be scanned """
    try:
        ip_start = raw_input("\033[1;37m[-]  Please enter the ip/domain to scan (example 192.168.0.1 or www.target.com)  : \033[1;m")

        DNS = gethostbyname(ip_start) #domain to ip thanks TylerP

        ip = IP(DNS)

        return ip
    except Exception as e:
        raise Exception(e)

def dnsEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected DNS on {0} : {1}\033[1;m'.format(ip_address, port))
    if port.strip() == "53":
        SCRIPT = "./Modules/dnsrecon.py {0!s}".format((ip_address))  # execute the python script
        subprocess.call(SCRIPT, shell=True)
    return


def httpEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected HTTP on {0} : {1}\033[1;m'.format(ip_address, port))
    checkpath("./results/")
    try:
        SCRIPT = "./Modules/httprecon.py {0!s} {1!s}".format(ip_address, port)  # execute the python script
        subprocess.call(SCRIPT, shell=True)
    except:
        pass
    return


def mssqlEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected SQL on {0} : {1}\033[1;m'.format(ip_address, port))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting MSSQL script scan for {0} : {1}\033[1;m'.format(ip_address, port))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    MSSQLSCAN = "nmap -vv -sV -Pn -p {0} --script-args=unsafe=1 --script=mysql-vuln-cve2012-2122.nse,ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username=sa,mssql.password=sa -oX ./results/{1}/{1}_mssql.xml {1}".format(port, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)
    outfile = "results/{0}/{0}_mssqlrecon.txt".format(ip_address)
    f = open(outfile, "w")
    f.write(results)
    f.close()
    return

def sshEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected SSH on {0} : {1}\033[1;m'.format(ip_address, port))
    SCRIPT = "./Modules/sshrecon.py {0!s} {1!s}".format(ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def telnetEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected TELNET on {0} : {1}\033[1;m'.format(ip_address, port))
    SCRIPT = "./Modules/telnetrecon.py {0!s} {1!s}".format(ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def snmpEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected SNMP on {0} : {1}\033[1;m'.format(ip_address, port))
    SCRIPT = "./Modules/snmprecon.py {0!s}".format((ip_address))
    subprocess.call(SCRIPT, shell=True)
    return


def smtpEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected SMTP on {0} : {1}\033[1;m'.format(ip_address, port))
    if port.strip() == "25":
        SCRIPT = "./Modules/smtprecon.py {0!s}".format((ip_address))
        subprocess.call(SCRIPT, shell=True)
    else:
        print '\033[1;33mWARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)\033[1;m'
    return


def smbEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected SMB on {0} : {1}\033[1;m'.format(ip_address, port))
    if port.strip() == "445":
        SCRIPT = "./Modules/smbrecon.py {0!s} 2>/dev/null".format((ip_address))
        subprocess.call(SCRIPT, shell=True)
    return


def ftpEnum(ip_address, port):
    #print('\033[1;34m[*]  Detected FTP on {0} : {1}\033[1;m'.format(ip_address, port))
    SCRIPT = "./Modules/ftprecon.py {0!s} {1!s}".format(ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return


def scanner(ip_address, protocol):
    ip_address = str(ip_address)
    checkpath("./results/{0}".format(ip_address))
    if not checknmaprun(ip_address, "{0}_nmap_scan_import.xml".format(protocol)):
        print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
        print('\033[1;37m[-]  |     Starting new {0} nmap scan for {1}\033[1;m'.format(protocol, ip_address))
        print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
        if protocol == "UDP":
            udpscan = "nmap -vv -Pn -sU -sV -A -O -p 53,67,68,88,161,162,137,138,139,389,520,2049 -oN './results/{0}/{0}U.nmap' -oX './results/{0}/{0}{1}_nmap_scan_import.xml' {0}".format(ip_address, protocol)
            with open(os.devnull, "w") as f:
                subprocess.call(udpscan, shell=True, stdout=f)
            udpresults = file("./results/{0}/{0}{1}_nmap_scan_import.xml".format(ip_address, protocol), "r")
            lines = udpresults
        else:
            tcpscan = "nmap -vv -Pn -A -O -sS -sV -p- --open -oN './results/{0}/{0}.nmap' -oX './results/{0}/{0}{1}_nmap_scan_import.xml' {0}".format(ip_address, protocol)
            with open(os.devnull, "w") as f:
                subprocess.call(tcpscan, shell=True, stdout=f)
            tcpresults = file("./results/{0}/{0}{1}_nmap_scan_import.xml".format(ip_address, protocol), "r")
            lines = tcpresults
    else:
        print('\033[1;33m[-]  {0} already scanned for {1} ports...\033[1;m'.format(ip_address, protocol))
        if protocol == "UDP":
            udpresults = file("./results/{0}/{0}{1}_nmap_scan_import.xml".format(ip_address, protocol), "r")
            lines = udpresults
        else:
            tcpresults = file("./results/{0}/{0}{1}_nmap_scan_import.xml".format(ip_address, protocol), "r")
            lines = tcpresults
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     {0} Nmap scan being parsed for {1}\033[1;m'.format(protocol, ip_address))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    logparser(ip_address, protocol)

    serv_dict = {}
    for line in lines:
        ports = []
        if (str(protocol).lower() in line) and ("open" in line) and ("service name=" in line) and not ("Discovered" in line):
            port = (re.search("portid=\"(.*?)\"", line))
            service = (re.search("service name=\"(.*?)\"", line))
            port = (port.group().split("\""))[1]
            service = (service.group().split("\""))[1]

            if service in serv_dict:
                ports = serv_dict[service]  # if the service is already in the dict, grab the port list

            if port not in ports:
                ports.append(port)
            serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)
            #print('\033[1;32m[*]  Open {0} port {1} found on {2}\033[1;m'.format(protocol, port, ip_address))

    # Go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if serv == "http" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif serv == "ssl/http" or "https" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(snmpEnum, ip_address, port)
        elif "domain" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(dnsEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip_address, port)
        elif "microsoft-ds" or "netbios-ssn" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum, ip_address, port)
        elif "telnet" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(telnetEnum, ip_address, port)
    return

def logparser(ip, protocol):
    from xml.etree import ElementTree
    from libnmap.parser import NmapParser

    with open ('./results/{0}/{0}{1}_nmap_scan_import.xml'.format(ip, protocol), 'rt') as file: #ElementTree module is opening the XML file
        tree = ElementTree.parse(file)

    rep = NmapParser.parse_fromfile('./results/{0}/{0}{1}_nmap_scan_import.xml'.format(ip, protocol)) #NmapParse module is opening the XML file
    #For loop used by NmapParser to print the hostname and the IP
    for _host in rep.hosts:
        host = ', '.join(_host.hostnames)
        ip = (_host.address)

        print "\033[1;32m[+]\033[1;37m  HostName: "'{0: >35}\033[1;m'.format(host,"--", ip)


    #Lists in order to store Additional information, Product and version next to the port information.
    list_product=[]
    list_version=[]
    list_extrainf=[]
    for node_4 in tree.iter('service'): #ElementTree manipulation. Service Element which included the sub-elements product, version, extrainfo
        product = node_4.attrib.get('product')
        version = node_4.attrib.get('version')
        extrainf = node_4.attrib.get('extrainfo')
        list_product.append(product)
        list_version.append(version)
        list_extrainf.append(extrainf)

    try:
        for osmatch in _host.os.osmatches: #NmapParser manipulation to detect OS and accuracy of detection.
            os = osmatch.name
            accuracy = osmatch.accuracy
            print "\033[1;32m[+]\033[1;37m  Operating System Guess: \033[1;m", os, "\033[1;37m- Accuracy Detection\033[1;m", accuracy
            break
    except:
        os = "Microsoft"
        print "\033[1;32m[+]\033[1;37m  ----------------------------------------------------------------------------- \033[1;m"
    try:
        if protocol == 'UDP':
            os = 'UDP'
        if 'Microsoft' in os:
            counter = 0
            for services in _host.services: #NmapParser manipulation to list services, their ports and their state. The list elements defined above are printed next to each line.
                #print "Port: "'{0: <5}'.format(services.port), "Product: "'{0: <15}'.format(list_product[counter],list_version[counter],list_extrainf[counter]), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <5}'.format(services.protocol)
                print "\033[1;32m[+]\033[1;37m  Port: "'{0: <5}\033[1;m'.format(services.port), "\033[1;37mState: "'{0: <5}\033[1;m'.format(services.state), "\033[1;37mProtocol: "'{0: <2}\033[1;m'.format(services.protocol),"\033[1;37mProduct: "'{0: <15}\033[1;m'.format(list_product[counter]),"\033[1;37mVersion: "'{0: <15}\033[1;m'.format(list_version[counter]),"\033[1;37mExtrInfo: "'{0: <10}\033[1;m'.format(list_extrainf[counter])
                findsploit(list_product[counter], list_version[counter])
                counter = counter + 1

        if 'Linux' in os:
            counter = 0
            for services in _host.services: #NmapParser manipulation to list services, their ports and their state. The list elements defined above are printed next to each line.
                #print "Port: "'{0: <5}'.format(services.port), "Product: "'{0: <15}'.format(list_product[counter],list_version[counter],list_extrainf[counter]), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <5}'.format(services.protocol)
                print "\033[1;32m[+]\033[1;37m  Port: "'{0: <5}\033[1;m'.format(services.port), "\033[1;37mState: "'{0: <5}\033[1;m'.format(services.state), "\033[1;37mProtocol: "'{0: <2}\033[1;m'.format(services.protocol),"\033[1;37mProduct: "'{0: <15}\033[1;m'.format(list_product[counter]),"\033[1;37mVersion: "'{0: <15}\033[1;m'.format(list_version[counter]),"\033[1;37mExtrInfo: "'{0: <10}\033[1;m'.format(list_extrainf[counter])
                findsploit(list_product[counter], list_version[counter])
                counter = counter + 1

        if 'UDP' in os:
            counter = 0
            for services in _host.services: #NmapParser manipulation to list services, their ports and their state. The list elements defined above are printed next to each line.
                #print "Port: "'{0: <5}'.format(services.port), "Product: "'{0: <15}'.format(list_product[counter],list_version[counter],list_extrainf[counter]), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <5}'.format(services.protocol)
                print "\033[1;32m[+]\033[1;37m  Port: "'{0: <5}\033[1;m'.format(services.port), "\033[1;37mState: "'{0: <15}\033[1;m'.format(services.state), "\033[1;37mProtocol: "'{0: <2}\033[1;m'.format(services.protocol),"\033[1;37mProduct: "'{0: <15}\033[1;m'.format(list_product[counter]),"\033[1;37mVersion: "'{0: <10}\033[1;m'.format(list_version[counter]),"\033[1;37mExtrInfo: "'{0: <10}\033[1;m'.format(list_extrainf[counter])
                findsploit(list_product[counter], list_version[counter])
                counter = counter + 1
    except:
        print('\033[1;31m[-]  NMAP parsing script {0} had some errors or no ports were found.\033[1;m'.format(ip))

def logparsertxt(results):
    lines = results.split("\n")
    for line in lines:
        if ("|" in line) or (" . " in line):
                print '\033[1;32m[+]  \033[1;37m' + line + '\033[1;m'
    return

def logparserfile(results):
    lines = results.read().strip().split('\n')
    for line in lines:
        if ("|" in line) or (" . " in line):
                print '\033[1;32m[+]  \033[1;37m' + line + '\033[1;m'
    return
def logparsernikto(results):
    lines = results.split("\n")
    for line in lines:
        if ("+" in line):
                print '\033[1;32m[+]  \033[1;37m' + line + '\033[1;m'
    return

def logparserall(results):
    lines = results.split("\n")
    for line in lines:
        print '\033[1;32m[+]  \033[1;37m' + line + '\033[1;m'
    return

def findsploit(product, version):
    found = []
    found2 = []

    try:
        majorversion = version.split(" ")
        majorproduct = product.split(" ")
        versiontop = majorversion[0].split(".")
        try:
            SCRIPT = "searchsploit {0} {1}| grep -v dos | grep remote".format(majorproduct[0], versiontop[0])  # find possible sploits
            sploitresults = subprocess.check_output(SCRIPT, shell=True)
            sploits = sploitresults.split("\n")

            for line in sploits:
                found.append(line)

            if len(found) <= 10:
                print('\033[1;32m[+]  \033[1;37m| Found the following exploits for \033[1;31m{0} {1}\033[1;m'.format(majorproduct[0], versiontop[0]))
                for item in found:
                    founditems = item.strip().split("|")
                    print "\033[1;32m[+]\033[1;37m  |_{0} {1}\033[1;m".format(founditems[0], founditems[1])

            else:
                print('\033[1;33m[-]  Found too many possible exploits for {0} {1} please check manualy\033[1;m'.format(majorproduct[0], versiontop[0]))
        except:
            SCRIPT2 = "searchsploit {0}| grep -v dos | grep remote".format(majorproduct[0])  # find possible sploits
            sploitresults2 = subprocess.check_output(SCRIPT2, shell=True)
            sploits2 = sploitresults2.split("\n")

            for line in sploits2:
                found2.append(line)
            if len(found2) <= 10:
                print('\033[1;32m[+]  \033[1;37m| Found the following exploits for \033[1;31m{0}\033[1;37m without version \033[1;m'.format(majorproduct[0]))

                for item in found2:
                    founditems = item.split("|")
                    print "\033[1;32m[+]\033[1;37m  |_{0} {1}\033[1;m".format(founditems[0], founditems[1])

            else:
                print('\033[1;33m[-]  Found too many possible exploits for {0} without version please check manualy\033[1;m'.format(majorproduct[0]))
    except:
        pass
    return

def screenshot_http(ip_address, port, header):
    path="./results/{0}/{0}_Screenshot_{1}.png".format(ip_address, port)
    if str(port) == "443":
        header = "https://"
    else:
        header = "http://"
    url ="{0}{1}:{2}".format(header, ip_address, port)
    try:
        try:
            driver = webdriver.Firefox()
            driver.get(url)
            driver.save_screenshot(path)
            driver.close()
        except:
            url = 'view-source:{0}'.format(url)
            driver.get(url)
            driver.save_screenshot(path)
    except:
        print('\033[1;31m[-]  Selenium script for {0}:{1} had some errors.\033[1;m'.format(ip_adress, port))
