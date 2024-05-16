#!/usr/bin/env python3
#Import scapy
from scapy.all import *

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
print("\n*            https://www.linkedin.com/in/nawwarmohammad/                                *")
print("\n*            https://github.com/NawwarMohammad                                          *")
print("\n**********************************SYRIA**************************************************")

ports = [25,80,53,443,445,8080,8443]
#port(25)   = SMTP     , Simple Mail Transfer Protocol: used for email routing between mail servers.
#port(80)   = HTTP     , Hypertext Transfer Protocol: uses TCP in versions 1.x and 2.HTTP/3 uses QUIC,a transport protocol on top of UDP.
#port(53)   = DNS      , Domain Name System
#port(443)  = HTTPS    , Hypertext Transfer Protocol Secure: uses TCP in versions 1.x and 2.HTTP/3 uses QUIC,a transport protocol on top of UDP.
#port(445)  = AD & SMB , Microsoft-DS (Directory Services) Active Directory,Windows shares ; Microsoft-DS (Directory Services) SMB file sharing.
#port(8080) = HTTP     , Alternative port for HTTP; Apache Tomcat; Atlassian JIRA applications. 
#port(8443) = HTTPS    , SW Soft Plesk Control Panel; Apache Tomcat SSL; Promise WebPAM SSL; iCal over SSL; MineOs WebUi.

#Implement a simple SYN scan similar to what you'd see in Nmap 
def SynScan(host):
    ans,unans = sr(IP(dst=host)/TCP(sport=5555,dport=ports,flags="S"),timeout=2,verbose=0)
    print ("Open ports at %s:" % host)
    for (s,r,) in ans:
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)
            
#there's going to be a half-open connection there, where we sent the SYN, they send the SYN-ACK, and we never send the final ACK.
#"sr" here to send the packet and wait for a reply.
#You can use a Wireshark filter to just look at traffic that is coming from or going to port 5555.
#This will do is it will send a SYN packet out to each of the ports in our list.
#We're specifying a flag of S saying that all we want sent in these packets that we're sending out is a SYN flag.
#We're setting a timeout saying that we only want to wait a couple of seconds for a response because the machine that we're port scanning in this particular case is #generally up. So we don't want to wait forever if there is no response to a particular packet because that just means the port's closed. 
#Setting verbose equal to zero. By default, SR is going to provide you with a lot of information and we don't really need that. All we really need is the result of #this called the SR.


#Implement to look for DNS servers.
def DNSScan(host):
    ans,unans = sr(IP(dst=host)/UDP(sport=5555,dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
    if ans:
        print ("DNS Server at %s" %host)

#Our simple DNS scan here is designed to connect to a particular port on a particular host and see if it properly responds to a DNS request.

#The target host is going to be the Google DNS server. 
host = "8.8.8.8"

SynScan(host)
DNSScan(host)






