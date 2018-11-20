#!/usr/bin/env python2.7b
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
# Additional contributions and enhancements from: Scott Nusbaum @TrustedSec
#
###################################################################################################

import sys
import os
import re
import urllib2
import ssl
import socket
import threading
import traceback
import argparse
from zipfile import ZipFile
from StringIO import StringIO
from multiprocessing import Pool
from datetime import datetime

################
# Global data
################
banlist = None
banlist_findings = {}
banlist_findings_lock = threading.RLock()
failed_ips = []
g_download_failed = True
b_stdout_lock = threading.RLock()

################
# Configuration Items
################
CPU_CORES = 16      # Arbitrary number
MAX_LINES = 10000   # Arbitrary number
use_remote = True
BASE_PATH = '' 

ALIEN_URL = 'https://reputation.alienvault.com'
BD_URL = 'https://www.binarydefense.com'
AMAZON_URL = 'http://s3.amazonaws.com'

ALIEN_FILE = 'reputation.unix'
TOR_FILE = 'tor.txt'
BANLIST_FILE = 'banlist.txt'
TOP_1M_FILE = 'alexa-static/top-1m.csv'

################
# Helper Functions
################

def printl( msg ):
    b_stdout_lock.acquire()
    print msg
    b_stdout_lock.release()

# unzip something
def download_unzip(input_zip):
    content = download_list( input_zip )
    unzipped_string = ''
    zipfile = ZipFile(StringIO( content ))
    for name in zipfile.namelist():
        unzipped_string += zipfile.open(name).read()
    return unzipped_string

# download something
def download_list(url):
    try:
        b_stdout_lock.acquire()
        print "Downloading %r ... " % url,
        req = urllib2.Request( url, None, {'User-agent': 'Mozilla/5.0' } )
        response = urllib2.urlopen( req )
        print "Complete"
        b_stdout_lock.release()
        return response.read()
    except:
        printl( "Error downloading url %r" % url )
        return None

def read_file( filename ):
    content = None

    if os.path.exists( filename ):
        fd = open( filename, 'r')
        content = fd.read()
        fd.close()
    
    return content

################################################################################
# Download the individual lists
################################################################################
# TODO:  Move all downloads and compairsons to their own class.
#        ie alexa will have a class inherited from a master ip_validator class
#        this will intern expose a download function and a search function.
#
#        Make a JSON file to hold the time that each file was downloaded.
        
def downlaod_alexa( ):
    if use_remote == True:
        url = ("%s/%s.zip" % (AMAZON_URL, TOP_1M_FILE ) )
        domains = download_unzip(url)
        with open( '%s%s%s' % ( BASE_PATH, os.sep, TOP_1M_FILE.replace('/','_') ), 'w' ) as fd:
            fd.write( domains )
    else: 
        domains = read_file( '%s%s%s' % ( BASE_PATH, os.sep, TOP_1M_FILE.replace('/', '_') ) )
    return domains

def download_binarybanlist( ):
    if use_remote == True:
        url = ("%s/%s" % (BD_URL, BANLIST_FILE ) )
        bd_banlist = download_list(url)
        with open( '%s%s%s' % ( BASE_PATH, os.sep, BANLIST_FILE), 'w' ) as fd:
            fd.write( bd_banlist)
    else:
        bd_banlist = read_file( '%s%s%s' % ( BASE_PATH, os.sep, BANLIST_FILE ) )

    return bd_banlist

def download_binarytorlist():
    if use_remote == True:
        url = ("%s/%s" % ( BD_URL, TOR_FILE ) )
        tor = download_list( url )
        with open( '%s%s%s' % ( BASE_PATH, os.sep, TOR_FILE ), 'w' ) as fd:
            fd.write( tor )
    else:
        tor = read_file( '%s%s%s' % ( BASE_PATH, os.sep, TOR_FILE)  )

    return tor

def download_otx():
    if use_remote == True:
        url = ("%s/%s" % ( ALIEN_URL, ALIEN_FILE ) )
        otx = download_list(url)
        with open( '%s%s%s' % ( BASE_PATH, os.sep, ALIEN_FILE ), 'w' ) as fd:
            fd.write( otx )
    else:
        otx = read_file( '%s%s%s' % ( BASE_PATH, os.sep, ALIEN_FILE) )

    return otx

################################################################################
# Search the individual lists
################################################################################

# TODO Multithread the search ??
# pulls the alexa top 1 million
def search_alexa( hostlist ):
    global banlist_findings
    global banlist_findings_lock
    domains = banlist[ 'alexa' ]

    if not 'alexa' in banlist_findings.keys():
        banlist_findings_lock.acquire()
        banlist_findings[ 'alexa' ] = []
        banlist_findings_lock.release()

    for hosts in hostlist:
        hosts = hosts.rstrip()
        if not hosts in domains:
            if hosts != "":
                banlist_findings_lock.acquire()
                banlist_findings[ 'alexa' ].append( hosts )
                banlist_findings_lock.release()

# pulls the binary defense banlist
def search_binarybanlist( hostlist ):
    global banlist_findings
    global banlist_findings_lock
    bd_banlist = banlist[ 'banlist' ] 

    if not 'tor' in banlist_findings.keys():
        banlist_findings_lock.acquire()
        banlist_findings[ 'banlist' ] = []
        banlist_findings_lock.release()

    for hosts in hostlist:
        hosts = hosts.rstrip()
        if hosts in bd_banlist:
            if hosts != "":
                banlist_findings_lock.acquire()
                banlist_findings[ 'banlist' ].append( hosts )
                banlist_findings_lock.release()

# pulls the binary defense torlist
def search_binarytorlist( hostlist ):
    global banlist_findings
    global banlist_findings_lock
    bd_tor = banlist[ 'torlist' ] 

    if not 'tor' in banlist_findings.keys():
        banlist_findings_lock.acquire()
        banlist_findings[ 'tor' ] = []
        banlist_findings_lock.release()

    for hosts in hostlist:
        hosts = hosts.rstrip()
        if hosts in bd_tor:
            if hosts != "":
                banlist_findings_lock.acquire()
                banlist_findings[ 'tor' ].append( hosts )
                banlist_findings_lock.release()

# get associated otx list
def search_otx( hostlist ):
    global banlist_findings
    global banlist_findings_lock
    otx = banlist[ 'otxlist' ] 

    if not 'otx' in banlist_findings.keys():
        banlist_findings_lock.acquire()
        banlist_findings[ 'otx' ] = []
        banlist_findings_lock.release()

    # FORMAT: ALL: 46.4.123.15 # Malicious Host
    for hosts in hostlist:
        hosts = hosts.rstrip()
        if hosts in otx:
            if hosts != "":
                banlist_findings_lock.acquire()
                banlist_findings[ 'otx' ].append( hosts )
                banlist_findings_lock.release()

################################################################################
# Thread function:  
#   Processes the file ip and hosts. 
#       If the input is an ip attempts to resolve the hostname
#       If the input is a hostname attmpts to resolve the IP
#       Both are stored and search against the lists
#   Called from the Pool.map object.
#   Input:  List of ip or hostnames
################################################################################
def pool_main( items ):
    ip_list = []
    host_list = []
    
    if not type( items ) == list:
        items = [ items ] 
    for item in items:
        item = item.strip()
        m = re.search("((\d{1,3}\.){3}\d{1,3})", item )
        if not m == None:
            # IP address format found add to list and attempt to locate hostname
            ip_list.append(  m.group(1)  )
            try:
                host_list.append( socket.gethostbyaddr( m.group(1) )[0] )
            except:
                failed_ips.append( m.group(1) )
        else:
            # Item was not in the ip format therefore consider it a hostname.
            # add hostname to list and try to find it's IP address
            m = re.search("(https?://)?(www\.)?(.*)", item )
            if not m == None:
                host_list.append( m.group(3) )
                try:
                    ip_list.append( socket.getostbyname( m.group(3) ) )
                except:
                    failed_ips.append( m.group(3) )
            else:
                failed_ips.append( item )

    return ( ip_list, host_list )                    

def search_feeds( ips, hosts=None ):

    # check ips to banlist
    search_bs_thread = threading.Thread( name='search_bs', 
                            target=search_binarybanlist, args=[ ips ] )
    search_bs_thread.setDaemon( True )
    search_bs_thread.start()

    # check tor to banlist
    search_tor_thread = threading.Thread( name='search_tor', 
                            target=search_binarytorlist, args=[ ips ] )
    search_tor_thread.setDaemon( True )
    search_tor_thread.start()

    # check OTX
    search_otx_thread = threading.Thread( name='search_otx', 
                            target=search_otx, args=[ ips ] )
    search_otx_thread.setDaemon( True )
    search_otx_thread.start()

    # check alexa hostnames
    if not hosts == None:
        search_alexa( hosts )

    search_otx_thread.join()
    search_tor_thread.join()
    search_bs_thread.join()

def download_feeds():
    global banlist
    global g_download_failed

    # TODO Add multithreading to the downloads
    try:
        l_alexa   = downlaod_alexa( )
        l_banlist = download_binarybanlist( )
        l_torlist = download_binarytorlist()
        l_otxlist = download_otx()
    except:
        traceback.print_exc()
        return
    if l_alexa == None or l_banlist == None or l_torlist == None or l_otxlist == None:
        printl( "A download failed" )
        return

    banlist = { 
                'alexa': l_alexa, 
                'banlist': l_banlist,
                'torlist': l_torlist,
                'otxlist': l_otxlist
                }
    g_download_failed = False

def print_flaged_ip( ):
    for key in banlist_findings.keys():
        if len( banlist_findings[ key ] ) == 0:
            continue

        print "###### %s ######" % key
        for i in banlist_findings[ key ]:
            print '\t%s' % i

    if len( failed_ips ) > 0:
        print "###### FAILED TO PROCESS ######" 
        for ip in failed_ips:
            print '\t%s' % ip 

def parse_ip_file( fileinput ):
    hostlist = []  
    iplist = []

    content_lines = ''
    # get IP or host list from file
    with open(fileinput, "r") as fd:
        content_lines= fd.readlines()

    # Set will allow us to create a list of unique ip's
    content_lines = list( set( content_lines ) )

    printl("[*] This part might take a bit... Converting hostnames " \
          "to IPs or IPs to hostnames. Be patient... " \
          "file contains [%d] lines" % len( content_lines ))

    # Break the contents of the file into manageble chunks.
    # This provides the most benifit when processing large files
    len_cl = len(content_lines)
    max_lines = MAX_LINES
    if len_cl < MAX_LINES:
        if len_cl/CPU_CORES < 1:
            max_lines = 1
        else:
            max_lines = len_cl/CPU_CORES 
    tmp = []
    for index in range( 0, len_cl, max_lines):
        if index+max_lines > len_cl:
            tmp.append( content_lines[index:] )
        else:
            tmp.append( content_lines[index:index+max_lines] )
            index += max_lines 
    content_lines = tmp

    pool = Pool( CPU_CORES )
    x = pool.map( pool_main, content_lines )
    for i in x:
        iplist.extend( i[0] )
        hostlist.extend( i[1] )

    return ( iplist, hostlist )

def main( fileinput ):
    try:
        # Download the ip files at the same time as processing the 
        # user supplied list of files. Saves a little time.
        download_handle = threading.Thread( name='download', 
                                target=download_feeds )
        download_handle.setDaemon( True )
        download_handle.start()
        ip_list, host_list = parse_ip_file( fileinput )

        download_handle.join()

        if g_download_failed:
            printl( "downloads failed" )
            return
        printl("[*] Checking Alexa, Artillery, TOR, and OTX...")

        search_feeds( ip_list, host_list )

        print_flaged_ip()

    except:
        traceback.print_exc()

def BANNER():
    print (r"""          /)  (\
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
    print ("\n\nGoatRider is a simple tool for doing a comparison of IP " \
           "addresses or hostnames to BDS Artillery Feeds, OTX, Alexa Top " \
           "1M, and TOR.")
    print ("\nINSTRUCTIONS: Pass a file that has a list of hostnames or IP " \
           "addresses and wait for the output to see if there are any matches")
    print ("Written by: Dave Kennedy (@HackingDave) from Binary Defense " \
           "(@BinaryDefense)")
    print 

def argParse():
    parser = argparse.ArgumentParser( )
    parser.add_argument( 'file', help='Input file containing list of IP\'s. One IP per line' )
    parser.add_argument( '-l', '--local', help='Use local BDS, OTX, TOR, and Alexa files', action='store_true' )
    parser.add_argument( '-i', '--IPData', help='Directory containing the needed files', default="IPData" )

    return parser.parse_args()

if __name__=="__main__":
    start_time = datetime.now()
    BANNER()
    try:
        # Must have a copy of openssl that supports tlsv1.2. tls_1.0 will 
        # be rejected by the binarydefense site
        # The following should raise an error if running an older version of tls
        if ssl.PROTOCOL_TLSv1_2:
            pass 
    except:
        print "\n\ngoatrider requires that openssl supports TLSv1.2. Please " \
              "upgrade your python openssl\n\n"
        sys.exit()

    args = argParse()
    try:
        BASE_PATH = args.IPData
        if not os.path.isdir( args.IPData ):
            os.mkdir( args.IPData )
        if args.local == True:
            if not os.path.isfile( '%s%s%s' % ( BASE_PATH, os.sep, TOR_FILE ) ) or \
                    not os.path.isfile( '%s%s%s' % ( BASE_PATH, os.sep, BANLIST_FILE ) ) or \
                    not os.path.isfile( '%s%s%s' % ( BASE_PATH, os.sep, ALIEN_FILE ) ) or \
                    not os.path.isfile( '%s%s%s' % ( BASE_PATH, os.sep, TOP_1M_FILE.replace('/','_') ) ):
                print "Needed OTX, TOR, Alexa Top 1 million, or BD Banlist not found. Downloading!"
                use_remote = True
            else:
                use_remote = False
            
        if os.path.isfile( args.file ):
            main( args.file )
        else:
            print "Provided File (%s) could not be found" % args.file
    except:
        print "Error"
        traceback.print_exc()
    end_time = datetime.now() - start_time
    print "Total execution time (%d.%d)" % ( end_time.seconds, end_time.microseconds )
