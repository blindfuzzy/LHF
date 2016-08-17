###This has been only tested on the newest Kali Linux Distro


#LHF: Low Hanging Fruit a recon tool for penetration testing


#To install dependencies:

./Install.sh

#To start: 

./LHF.py

```python
[+]  Checking permissions
[-]  Rockyou wordlist is missing trying to decompress...
[+]  Rockyou wordlist is decompressed!
[-]  Please enter the ip to scan (example 192.168.0.1)  : <target ip here>
```
##A "results" folder will be created after inputting the target ip. This folder can be found in the Recon directory. 

Example:
```bash
cd /opt/LHF/results
```

The results output includes nmap files...arachni files..nikto files..pretty much every fucking file from every scan the tools does can be found in this folder. 

###This tool is meant to be "modular" i.e. you can add a new tool in the Modules folder and then add it into the LHF.py file and it will be included in the scan. 

####This tool will only scan a single IP at a time for the moment. I did this for testing purposes and because I am lazy.

####FYI, it will look like it's not doing anything but it actually is...I have nothing in place such as a progress bar. Output will stream as tasks are ran/completed. 

#To Do:
+ Test on other security distros 
+ Implement "pip install"
+ Add new features
+ Implement ip range/domain scanning

