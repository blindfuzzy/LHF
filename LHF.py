#!/usr/bin/env python
'''
RECON (WIP)
'''

from Modules import recon
import logging
from Queue import Queue
import threading
 
recon.bootstrap()

print "#####################################################\n"
print "[!] Usage: \n"
print "Enter Intial IP (i.e. '192.168.1.'): 192.168.1.\n"
print "Enter IP Range 1: 1\n"
print "Enter IP Range 2: 50\n"
print "Example of scanning 192.168.1.1 - 192.168.1.50\n"
print "#####################################################\n"


host = raw_input("Enter Intial IP (i.e. '192.168.1.'): ")

ip1 = int(raw_input("Enter IP Range 1: "))

ip2 = int(raw_input("Enter IP Range 2: "))

def Start(host):

    lock = threading.RLock()

    try:
        if __name__ == '__main__':
            try:
                recon.checkpath("./results/")
                recon.checkpreq()
            except:
                pass

            try:
                recon.startrecon()
            except:
                ips = recon.getIp(host)

                for ip in (str(ips)).split():
                    recon.scanner(ip, 'TCP')
                    recon.scanner(ip, 'UDP')

    except:
        recon.killrecon()
    finally:
        recon.finnished()

def Worker():

    while True:

        IPs = q.get()

        Start(str(host) + str(IPs))
        #Start(host)

        q.task_done()


q = Queue()

threads = int(3) # Threads

for x in range(threads + 1):

    t = threading.Thread(target=Worker, args=())
    t.daemon = True
    t.start()

for IPs in range(ip1, ip2 + 1):

    q.put(IPs)

q.join()
