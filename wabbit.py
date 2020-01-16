#!/usr/bin/python3
import requests
import sys
import socket
import whois
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import json
from pysafebrowsing import SafeBrowsing

gsb_apikey = ""

user_agent = {'User-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 Chrome/36.0.1985.125 Safari/537.36'}
content_type = {'Content-Type': 'application/json'}

print("\n\n                                                           ")
print("      .'...                                 ..'..          ")
print("     .dKK0Okdc,.                      .':oxO0KKO;          ")
print("      :OXXXXNNXKkl,.               .cd0XNNNXXXKd.          ")
print("       ,kXNNNNNNNNXOl.          .;xXNNNNNNNNN0l.           ")
print("        .cONWWWWWNNNW0c.       ,xNWNNWWWWWNKd'             ")
print("          .;oOXWWWWWWWNx.    .cKWWWWWWWN0xc.               ")
print("             ..,coxKNWWW0doookNWWWNOdl;'.                  ")
print("                 .:kNMMMWWMMMMMMMWXd,.                     ")
print("               .oKNWMMMMMMMMMMMMMMWWNO:.                   ")
print("              :0WWWMMMMMMMMMMMMMMMMWWWNk'                  ")
print("             cXWN0ooOWMMMMMMMMMMMXxlxXWNO,                 ")
print("            'OWWO;co,dWMMMMMMMMMXc;o;cKWNd.                ")
print("            ,0WNo.lx.;XMMMMMMMMMO.;k;.kWNx.                ")
print("            .dNNx....lNMMMWMMWWMK; ..;0NXc                 ")
print("             .oKXklcxXWW0c;;;lKWWKoco0XKl.                 ")
print("               'lx0NWWWWXkoloONWWWNN0xl'                   ")
print("      ':,..'.     .';cldXNXKXN0occ;'.     .'..,;.          ")
print("   .ldONX00XO:.         ;l:,cl.         .l0X00NXxo:.       ")
print("   .''cxllOOxkx;'cxxo:.         'ldxd;':kkx0kcod:..        ")
print("          .. .';OWWMMWKdc'. .,lkXWWWWNd,.. ..              ")
print("               .oNWMWMMMWNOdxO0KWMWWWK:                    ")
print("                 'cdxKNMMWMMWNKOOkxo:.                     ")
print("                  .;d00000XXNMMWN0l'.                      ")
print("               .,l0NXKOd;..',:lk0KXXkc.                    ")
print("               :xdc:'.          ..,:ldd'                   \n\n")

print ("(W)hois (A)SN (B)lacklist (B)ulk (I)nquiry (T)ool\n")
print ("Now running lookups...")
print ("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")

try:
    targets = sys.argv[1]
except:
    print ("!!  ERROR   !!")
    sys.exit()

registrant_email_table = []
user_agent = {'User-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 Chrome/36.0.1985.125 Safari/537.36'}


def whois_lookup(domainname):
    try:
        nameservers = []
        nameserver1 = ""
        nameserver2 = ""
        nameserver3 = ""
        nameserver4 = ""
        registrant_emails = []
        registrant_email1 = ""
        registrant_email2 = ""
        registrant_email3 = ""
        registrant_email4 = ""
        registrant_name1 = ""
        registrant_address = ""
        registrant_country = ""
        state = ""
        orgname1 = ""
        emailindex = 1
        nsindex = 1
        try:
            w = whois.whois(domainname)
        except:
            pass
        try:
            created_date = w.creation_date
            try:
                if len(created_date) == 2:
                    created_date = created_date[0]
            except:
                pass
        except:
            pass
            created_date = "1969-12-31 00:00:00"
        try:
            expired_date = w.expiration_date
            try:
                if len(expired_date) == 2:
                    expired_date = expired_date[0]
            except:
                pass
        except:
            pass
            expired_date = "1969-12-23 00:00:00"
        try:
            registrant_name1 = w.name.encode("ascii")
        except:
            pass
            registrant_name1 = ""
        try:
            registrant_address = w.address.encode("ascii")
        except:
            pass
            registrant_address = ""
        try:
            registrant_country = w.country.encode("ascii")
        except:
            pass
            registrant_country = ""
        try:
            state = w.state.encode("ascii")
        except:
            pass
            state = ""
        try:
            orgname1 = w.org.encode("ascii")
        except:
            pass
            orgname1 = ""
        try:
            whois_city = w.city.encode("ascii")
        except:
            pass
            whois_city = ""
        try:
            whois_zipcode = w.zipcode.encode("ascii")
        except:
            pass
            whois_zipcode = ""
        try:
            whois_registrar = w.registrar.encode("ascii")
            if len(whois_registrar) < 4:
                whois_registrar = whois_registrar[0].encode("ascii")
            whois_ref_url = w.referral_url.encode("ascii")
        except:
            pass
            whois_registrar = ""
            whois_ref_url = ""
        try:
            nameservers = w.name_servers.encode("ascii")
        except:
            pass
            nameservers = ""
        try:
            nameserver1 = w.name_servers[0].encode("ascii")
        except:
            pass
            nameserver1 = ""
        try:
            nameserver2 = w.name_servers[1].encode("ascii")
        except:
            pass
            nameserver2 = ""
        try:
            nameserver3 = w.name_servers[2].encode("ascii")
        except:
            pass
            nameserver3 = ""
        try:
            nameserver4 = w.name_servers[3].encode("ascii")
        except:
            pass
            nameserver4 = ""
        try:
            registrant_emails = w.emails
            if len(registrant_emails) > 5:
                registrant_email1 = w.emails
                registrant_email_table.append(registrant_email1)
            else:
                for registrant_email in registrant_emails:
                    registrant_email_table.append(registrant_email)
                    if emailindex == 1:
                        registrant_email1 = registrant_email
                    if emailindex == 2:
                        registrant_email2 = registrant_email
                    if emailindex == 3:
                        registrant_email3 = registrant_email
                    if emailindex == 4:
                        registrant_email4 = registrant_email
                    emailindex = emailindex + 1
        except:
            pass
    except:
        pass
    try:
        try:
            domain_ipaddr = socket.gethostbyname(domainname)
        except:
            pass
            domain_ipaddr = "- -"
        if domain_ipaddr != "- -":
            obj = IPWhois(domain_ipaddr)
            results = obj.lookup_whois()
            domain_asnid = "AS" + results['asn']
            if domain_asnid == "":
                domain_asnid = ""
            try:
                domain_country = results['asn_country_code']
                if domain_country == "":
                    domain_country = "- -"    
            except:
                domain_country = "- -"
                pass
            try:
                domain_asn_name = results['nets'][0]['name']
                if domain_asn_name == "":
                    domain_asn_name = "- -"
            except:
                domain_asn_name = "- -"
                pass
        else:
            domain_asnid = "- -"
            domain_country = "- -"
            domain_asn_name = "- -"
    except:
        pass
        domain_asnid = "- -"
        domain_asnid = "- -"
        domain_country = "- -"
        domain_asn_name = "- -"
    #################### BLACKLIST FUNCTION BELOW ##################
    try:
        url = "https://www.urlvoid.com/scan/" + domainname + "/"
        results = requests.get(url, headers=user_agent).content
        soup = BeautifulSoup(results, 'html.parser')
        t = soup.find('span',{'class':'label-danger'})
        urlvoid_bl = "URLVOID: " + t.text
        print(urlvoid_bl)
        #return urlvoid_bl
    except:
        pass
        urlvoid_bl = ""
    try:
        url2 = "https://fortiguard.com/webfilter?q=" + domainname + "&version=8"
        results2 = requests.get(url2, headers=user_agent).content
        soup2 = BeautifulSoup(results2, 'html.parser')
        t2 = soup2.find("meta", property="description")
        fortiguard = "FORTIGUARD " + str(t2["content"]) 
        print(fortiguard)
        #return fortiguard
    except:
        pass
        fortiguard = ""
    try:
        url3 = "http://www.siteadvisor.com/sitereport.html?url=" + domainname
        results3 = requests.get(url3, headers=user_agent).content
        soup3 = BeautifulSoup(results3, 'html.parser')
        t3 = soup3.find('a').contents[0]
        siteadvisor_bl = "SITEADVISOR: " + str(t3)
        print(siteadvisor_bl)
        #return fortiguard
    except:
        pass
        siteadvisor_bl = ""
    try:
        gsb_lookup = SafeBrowsing(gsb_apikey)
        results4 = gsb_lookup.lookup_urls([domainname])
        gsb_status = str(results4[domainname]['malicious'])
        gsb_platforms = results4[domainname]['platforms'][0].encode("ascii")
        gsb_threats = results4[domainname]['threats'][0].encode("ascii")
        print("GOOGLE SAFE BROWSING API4: " + gsb_status + " || " + gsb_platforms + " || " + gsb_threats)
    except:
        pass
        gsb_status = ""
        gsb_platforms = ""
        gsb_threats = ""
    output = domainname + ";" + orgname1 + ";"  + registrant_name1 + ";" + registrant_email1 + ";" + registrant_email2 + ";" + registrant_email3 + ";" + registrant_email4 + ";" + registrant_country + ";" + whois_city + ";" + whois_zipcode+ ";" +  nameserver1 + ";" + nameserver2 + ";" +  domain_ipaddr + ";" + domain_asnid + ";" + domain_asn_name + ";" + domain_country + ";" + gsb_status + ";" + gsb_platforms + ";" + gsb_threats + ";" + fortiguard + ";" + urlvoid_bl + ";" + siteadvisor_bl + "\n"
    filename1 =  "WABBIT-LOOKUP-RESULTS.csv"
    with open (filename1, "a") as outputfile:
        outputfile.write(output)
    output = ""

inputfile = open(targets, "r")
all_doms = inputfile.readlines()
all_doms = set(all_doms)
inputfile.close()

for domainname in all_doms:
    domainname = domainname.strip("\n")
    print ("\n" + domainname + ":")
    whois_lookup(domainname)


print ("\n\n-=-=-=-=-   WABBIT HAS COMPLETED ALL LOOKUPS!  -=-=-=-=-\n\n")

sys.exit()

