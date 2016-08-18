#!/usr/bin/env bash

find . -iname \*.py | xargs chmod +x

if [[ "$(uname -r)" == "4.0.0-kali1-amd64" ]] ; then
   echo -e "[+]  Installing package dependencies..."
   apt-get install arachni dirb nmap hydra sqlmap enum4linux nikto python
   pip install python-libnmap selenium

else
   echo "ERROR - This tool is intended for Kali Linux 4.0.0-kali1-amd64, it might not work as aspected"
   echo -e "[+]  Installing package dependencies..."
   apt-get install arachni dirb nmap hydra sqlmap enum4linux nikto python
   pip install python-libnmap selenium
fi
