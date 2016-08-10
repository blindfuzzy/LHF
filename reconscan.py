#!/usr/bin/env python
'''
RECON (WIP)
'''

from Modules import recon

recon.bootstrap()

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
            ips = recon.getIp()

            for ip in (str(ips)).split():
                recon.scanner(ip, 'TCP')
                recon.scanner(ip, 'UDP')

except:
    recon.killrecon()
finally:
    recon.finnished()


