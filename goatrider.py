#!/usr/bin/python
##################################################################################################
#
# This tool does a comparison of multiple sites to look for abnormal IP addresses or hostnames
#
# Current list checks:
#	Alexa Top 1 Million
#	Binary Defense Systems Banlist
#	Binary Defense Systems Tor List
#	OTX AlienVault
#
# Written by Dave Kennedy @ Binary Defense Systems (@BinaryDefense @HackingDave)
#
###################################################################################################

import urllib
import socket
from zipfile import ZipFile
from StringIO import StringIO
import sys
import os

# unzip something
def download_unzip(input_zip):
    url = urllib.urlopen(input_zip)
    unzipped_string = ''
    zipfile = ZipFile(StringIO(url.read()))
    for name in zipfile.namelist():
        unzipped_string += zipfile.open(name).read()
    return unzipped_string

# download something
def download_list(url):
    response = urllib.urlopen(url)
    return response.read()

# pulls the alexa top 1 million
def pull_alexa(hostlist):
    url = ("http://s3.amazonaws.com/alexa-static/top-1m.csv.zip")
    domains = download_unzip(url)
    hostfile = hostlist.split("\n")
    for hosts in hostfile:
        hosts = hosts.rstrip()
        if not hosts in domains:
            if hosts != "":
                print(("ALEXA_NOT_FOUND_HIT_HOST: %s" % (hosts)))

# pulls the binary defense banlist
def pull_binarybanlist(hostlist):
    url = ("https://www.binarydefense.com/banlist.txt")
    banlist = download_list(url)
    hostfile = hostlist.split("\n")
    for hosts in hostfile:
        hosts = hosts.rstrip()
        if hosts in banlist:
            if hosts != "":
                print(("ARTILLERY_BANLIST_HIT_IP: %s" % (hosts)))

# pulls the binary defense torlist
def pull_binarytorlist(hostlist):
    url = ("https://www.binarydefense.com/tor.txt")
    tor = download_list(url)
    hostfile = hostlist.split("\n")
    for hosts in hostfile:
        hosts = hosts.rstrip()
        if hosts in tor:
            if hosts != "":
                print(("ARTILLERY_TOR_HIT_IP: %s" % (hosts)))

# get associated otx list
def pull_otx(hostlist):
    url = ("https://reputation.alienvault.com/reputation.unix")
    otx = download_list(url)
    # FORMAT: ALL: 46.4.123.15 # Malicious Host
    hostfile = hostlist.split("\n")
    for hosts in hostfile:
        hosts = hosts.rstrip()
        if hosts in otx:
            if hosts != "":
                print(("AV_OTX_HIT_IP: %s" % (hosts)))

# get the associated IP address to hostname
def get_ip(hostname):
    ips = ""
    for host in hostname:
        host = host.rstrip()
        try:
            addr = socket.gethostbyname(host)

            ips = (ips + str(addr) + "\n")
        except:
            pass
    return ips

# get associated ip address from hostname
def get_host(ip):
    ips = ""
    for host in ip:
        host = host.rstrip()
        try:
            addr = socket.gethostbyaddr(host)
            addr = addr[0]
            addr = addr.replace(
                "https://", "").replace("http://", "").replace("www.", "")
            ips = ips + str(addr + "\n")

        except:
            pass

    return ips

try:

    fileinput = sys.argv[1]
    if os.path.isfile(fileinput):

        # get IP or host list from file
        filename = open(fileinput, "r").readlines()

        print("[*] This part might take a bit... Converting hostnames to IPs or IPs to hostnames. Be patient...")
        # determine if host file
        counter = 0
        for line in filename:
            try:
                socket.inet_aton(line)

            # using hostnames
            except:
                counter = 1
                break

        # if we are using hostnames
        if counter == 1:
            host = ""
            for hosts in filename:
                hosts = hosts.replace(
                    "https://", "").replace("http://", "").replace("www.", "")
                host = host + hosts + "\n"

            hostlist = host
            iplist = get_ip(filename)

        # else we are using iplists
        if counter == 0:
            # get hostname list from file
            hostlist = get_host(filename)
            ips = ""
            for ip in filename:
                ips = ips + ip + "\n"
            iplist = ips

        print("[*] Checking Alexa, Artillery, TOR, and OTX...")

        # check ips to banlist
        pull_binarybanlist(iplist)

        # check tor to banlist
        pull_binarytorlist(iplist)

        # check OTX
        pull_otx(iplist)

        # check alexa hostnames
        pull_alexa(hostlist)

    # if the file isnt there
    else:
        print ("Filename was not found, please specify the right path and try again.")
        sys.exit()

except:
    print (r"""      /)  (\
 )\.:::::::::./(
 \( o       o )/
   '-./ / _.-'`-.
    ( oo  ) / _  \
    |'--'/\/ ( \  \
     \''/  \| \ \  \
      ww   |  '  )  \
           |.' .'   |
          .' .'==|==|
         / .'\    [_]
      .-(/\) |     /
     /.-''''/|    |
     ||    / |    |
     //   |  |    |
     ||   |__|___/
     \\   [__[___]
     // .-'.-'  (
     ||(__(__.-._)""")
    print ("\n\nGoatRider is a simple tool for doing a comparison of IP addresses or hostnames to BDS Artillery Feeds, OTX, Alexa Top 1M, and TOR.")
    print ("\nINSTRUCTIONS: Pass a file that has a list of hostnames or IP addresses and wait for the output to see if there are any matches")
    print ("Written by: Dave Kennedy (@HackingDave) from Binary Defense (@BinaryDefense)")
    print ("\nUsage: python goatrider.py <hostnames_or_ips.txt>")
