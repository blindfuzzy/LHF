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
[-]  Please enter the ip to scan (example 192.168.0.1 or www.target.com)  : <target ip/url here>
```
+You can now scan a URL
+Working on the speed of things

##A "results" folder will be created after inputting the target ip. This folder can be found in the LHF directory. 

Example:
```bash
cd /opt/LHF/results
```
+Highly, reccomended you clone this into your /opt folder in Kali until I fix the code...unless you feel like changing the code round to whatever directory you have it in. This is low priority at the moment. 

The results output includes nmap files...arachni files...pretty much every fucking file from every scan the tools does can be found in this folder. 

###This tool is meant to be "modular" i.e. you can add a new tool in the Modules folder and then add it into the LHF.py file and it will be included in the scan. 

####This tool will only scan a single IP at a time for the moment. I did this for testing purposes and because I am lazy.

####FYI, it will look like it's not doing anything but it actually is...I have nothing in place such as a progress bar. Output will stream as tasks are ran/completed. 

#To Do:
+ Test on other security distros 
+ Implement "pip install"
+ Add new features
+ Implement ip range/domain scanning

#New (08/22/2016):
+Domain Scanning (still working on ip range scanning aka /24 stuff. 
+Load Balancer detector (note: saw lots of false negatives when "www" is used before the url. Reccomend you skip using that.)
+Got rid of Nikto it pumps out the same results as Arachni and slows things down. 
+We now have a beta-testing branch...I deffinitely don't reccomend cloning from that branch as it is highly unstable, unless of course you would like to help in the development of LHF. Once things in that branch are thoroughly tested we will push things out to the master branch.


Keep reporting issues they help.
Thanks to everyone who has downloaded this. 
