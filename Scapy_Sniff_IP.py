from scapy.all import IP, sniff
from scapy.layers import http
import sqlite3 as sql3

counter = 0

def customAction(packet):
    global counter

    counter += 1
    if(packet[0][1].proto == 1):
        proto_ = 'ICMP'
    elif(packet[0][1].proto == 2):
        proto_ = 'IGMP'
    elif(packet[0][1].proto == 3):
        proto_ = 'GGP'
    elif(packet[0][1].proto == 4):
        proto_ = 'IPv4'
    elif(packet[0][1].proto == 5):
        proto_ = "ST"
    elif(packet[0][1].proto == 6):
        proto_ = "TCP"
    elif(packet[0][1].proto == 7):
        proto_ = 'CBT'
    elif(packet[0][1].proto == 8):
        proto_ = 'EGP'
    elif(packet[0][1].proto == 12):
        proto_ = 'PUP'
    elif(packet[0][1].proto == 15):
        proto_ = 'XNET'
    elif(packet[0][1].proto == 17):
        proto_ = 'UDP'
    elif(packet[0][1].proto == 21):
        proto_ = 'FTP'
    elif(packet[0][1].proto == 22):
        proto_ = 'SSH'
    elif(packet[0][1].proto == 23):
        proto_ = 'TELNET'
    elif(packet[0][1].proto == 25):
        proto_ = 'SMTP'
    elif(packet[0][1].proto == 28):
        proto_ = 'IRTP'
    elif(packet[0][1].proto == 33):
        proto_ = 'DCCP'
    elif(packet[0][1].proto == 35):
        proto_ = 'IDPR'
    elif(packet[0][1].proto == 36):
        proto_ = 'XTP'
    elif(packet[0][1].proto == 37):
        proto_ = 'DDP'
    elif(packet[0][1].proto == 38):
        proto_ = 'IDPR-CMTP'
    elif(packet[0][1].proto == 41):
        proto_ = 'IPv6'
    elif(packet[0][1].proto == 42):
        proto_ = 'SDRP'
    elif(packet[0][1].proto == 43):
        proto_ = 'IPv6-Route'
    elif(packet[0][1].proto == 44):
        proto_ = 'IPv6-Frag'
    elif(packet[0][1].proto == 45):
        proto_ = 'IDRP'
    elif(packet[0][1].proto == 53):
        proto_ = 'DNS'
    elif(packet[0][1].proto == 56):
        proto_ = 'TLSP'
    elif(packet[0][1].proto == 58):
        proto_ = 'IPV6-ICMP'
    elif(packet[0][1].proto == 71):
        proto_ = 'IPVC'
    elif(packet[0][1].proto == 75):
        proto_ = 'PVP'
    elif(packet[0][1].proto == 80):
        proto_ = 'HTTP'
    elif(packet[0][1].proto == 84):
        proto_ = 'TTP'
    elif(packet[0][1].proto == 92):
        proto_ = 'MTP'
    elif(packet[0][1].proto == 118):
        proto_ = 'STP'
    elif(packet[0][1].proto == 123):
        proto_ = 'PTP'
    elif(packet[0][1].proto == 126):
        proto_ = 'CRTP'
    elif(packet[0][1].proto == 131):
        proto_ = 'PIPE'
    elif(packet[0][1].proto == 132):
        proto_ = 'SCTP'
    elif(packet[0][1].proto == 143):
        proto_ = 'ETHERNET'
    else:
        proto_ = 'null'
            
      
    #result = 'Packet #{}: {} ==> {} ==> {} ==> {} ==> {} ==> {} ===> {} =====> {}'.format(counter, str(packet[0][1].src), str(packet[0][1].dst), str(packet[0][1].len), str(packet[0][1].ttl), str(proto_), str(packet[0][1].chksum),str(packet[0][1].flags),str(packet[0][1].version))
    return 'Packet #{}: {} ==> {} ==> {} ==> {} ==> {} ==> {} ===> {} =====> {}'.format(counter, str(packet[0][1].src), str(packet[0][1].dst), str(packet[0][1].len), str(packet[0][1].ttl), str(proto_), str(packet[0][1].chksum),str(packet[0][1].flags),str(packet[0][1].version))
    

sniff(filter='ip', prn=customAction)  



