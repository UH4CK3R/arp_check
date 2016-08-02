import time,commands
import netifaces as neti
from scapy.all import *

arp_spoof = ARP()

eth = neti.interfaces()[1]

def arp_broadcast(g_ip,s_ip,s_mac): #Get Recever's Mac
    arp_bro = ARP()

    arp_bro.hwsrc = s_mac
    arp_bro.hwdst = "ff:ff:ff:ff:ff:ff"
    arp_bro.psrc = s_ip
    arp_bro.pdst = g_ip

    packet = sr1(arp_bro)

    return packet[ARP].hwsrc

def main():
    s_ip = neti.ifaddresses(eth)[neti.AF_INET][0]['addr']
    s_mac = neti.ifaddresses(eth)[neti.AF_LINK][0]['addr']
    g_ip = neti.gateways()[neti.AF_INET][0][0]
    g_mac_origin = arp_broadcast(g_ip,s_ip,s_mac)

    while(1):
        g_mac = commands.getstatusoutput("arp -n | grep "+g_ip+" | awk {'print $3'}")[1][0:17]
        if g_mac != g_mac_origin:
            print "========================"
            print "ARP Table was Changed!!"
            print "========================"
        time.sleep(1)

if __name__ == '__main__':
    main()
