#!/usr/bin/env python3
# The dns module in Python allows to query DNS servers directly.
import dns
#To look up a particular domain name. 
import dns.resolver
# The socket module in Python is an interface to the Berkeley sockets API.
import socket

# Basic user interface header
print(r"""
_______    ____         ___         ___         ___  ___         ___         ___
|      \   |  |         \  \       /   \       /  /  \  \       /   \       /  /            ____ __ 
|  |\   \  |  |  _____   \  \     /  /\ \     /  /    \  \     /  /\ \     /  /      ____   |  /  /
|  |  \  \ |  |  / _` \   \  \   /  /  \ \   /  /      \  \   /  /  \ \   /  /      / _` \  |  __/
|  |   \  \|  | | (_| |    \  \_/  /    \ \_/  /        \  \_/  /    \ \_/  /      | (_| |  |  |
|__|    \_____|  \__,_|     \_____/      \____/          \_____/      \____/        \__,_|  |__|""")
print("\n**********************************SYRIA**************************************************")
print("\n*            Copyright of Nawwar Mohammad, 2023                                         *")
print("\n*            https://www.linkedin.com/in/nawwar-mhm-n35336249                           *")
print("\n*            https://github.com/NawwarMohammad                                          *")
print("\n**********************************SYRIA**************************************************")

#Use Python to perform reconnaissance and gain information about a target organization using the domain name system or DNS.
#DNS is essentially the phonebook of the internet.
#we can learn about the IP ranges that belong to a particular organization, the types of systems that are at particular IP addresses etc. And this information is #invaluable for planning an attack or a testing exercise against a particular organization.
#base domain here google.com and try common subdomains like mail.google.com


def ReverseDNS(ip):
    try:
        result = socket.gethostbyaddr(ip)
    except:
        return []
    return [result[0]]+result[1]
    
#A record which is the most common type of record.    
def DNSRequest(domain):
     try:
         result = dns.resolver.resolve(domain,'A')
         if result:
             print(domain)
             for answer in result:
                 print(answer)
                 print("Domain Names: %s" % ReverseDNS (answer.to_text()))
     except (dns.resolver.NXDOMAIN, dns.exception.Timeout) :
         return
        
#for some subdomains, it's common for them to have a number appended at the end, for example, having subdomains like ns1.google.com, ns2.google.com, etc, to indicate #different name servers on Google's network. And the list of subdomains that we put together doesn't have those numbers in it.          
def SubdomainSearch(domain, dictionary,nums):
    for word in dictionary:
        subdomain = word+"."+domain
        DNSRequest(subdomain)
        if nums:
            for i in range (0,10) :
                s = word+str(i)+"."+domain
                DNSRequest(s)
                
domain = "google.com"
#subdomains.txt we're going to be building a collection of subdomains, especially common subdomains, and then asking the DNS infrastructure if that particular #subdomain exists. 
d = "subdomains.txt"
dictionary = []
with open(d,"r") as f:
    dictionary = f.read().splitlines()
SubdomainSearch (domain, dictionary,True)                       
