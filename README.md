# wabbit
Python3 script that will perform a bulk Domain Whois & ASN Lookup along with Blacklist check based on provided list of domain names.

     Language: Python 3
     Libraries: requests, sys, socket, whois, IPWhois, BeautifulSoup, json, pysafebrowsing
     Purpose: OSINT - Whois, ASN & Blacklist Checker


# Install
Follow the steps below to install 'wabbit'.

     git clone https://github.com/lostrabbitlabs/wabbit
     cd wabbit
     chmod 655 wabbit.py
     pip3 install whois
     pip3 install IPWhois
     pip3 install bs4
     pip3 install pysafebrowsing


# Usage
Simply provide a target file with one (1) domain name per line and run the script.

     ./wabbit.py targets.txt


SAMPLE targets.txt:

     example.com
     example2.com
     example3.com


# Output
When completed will create a CSV output file with the following information per domain:

     Domain Whois Lookup
     ASN/IPWhois Lookup
     Blacklist Lookup (URLVoid, SiteAdvisor, Fortiguard, and optionally Google Safe Browsing API v4)

# Bonus
In order to use the Google Safe Browsing API you need to modify the 'gsb_apikey' value in wabbit.py. More information about GSB API v4 below:

     https://developers.google.com/safe-browsing/v4/get-started


