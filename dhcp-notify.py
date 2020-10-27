#!/usr/bin/env python3
"""dhcp-notify.py
Provides easy DHCP monitoring and reporting.

DHCP Monitoring:
Listens for DHCP packets on a LAN by using scapy to monitor when hosts
send DHCP requests for IP addresses from DHCP servers.

Real-Time Reporting:
dhcp-notify uses PycURL to interact with the Telegram Bot API.
This allows for real-time reporting of DHCP activity sent via
text message in Telegram. Allowing for remote reporting to mobile
device easily.

License: GNU GPLv3, 0BSD

2020 Logan Elliott
"""

from __future__ import print_function
from urllib.parse import urlencode
from scapy.all import *
import time
import pycurl
import os
import sys
import argparse

__version__ = "0.0.1"

# Configure program arguments
parser = argparse.ArgumentParser(description="Real-time DHCP monitoring and reporting through Telegram")
parser.add_argument("API_key", help="API key for Telegram bot")
parser.add_argument("chat_id", help="ID of chat for notifications to be sent to")
args = parser.parse_args()

api_key = args.API_key
usrchat_id = args.chat_id

print("dhcp-notify: Real-time DHCP monitoring and reporting through Telegram\n")

    
print("*-* DHCP packet sniffing initialized *-*\n")
# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):

    must_decode = ['hostname', 'domain', 'vendor_class_id'] # RFC2132: Hostname DHCP option #12, domain DHCP option #6, Vendor Class ID DHCP option #60
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass

# Function for PycURL to send request to Telegram Bot API when DHCP traffic is sniffed
def curl_sendmsg(text_data,data):
    curl_dhcp = pycurl.Curl()
    curl_dhcp.setopt(curl_dhcp.URL, 'https://api.telegram.org/bot'+api_key+'/sendMessage')
    encode = urlencode(data)
    # Send a POST request
    # Set Content-Type header to application/x-www-form-urlencoded
    curl_dhcp.setopt(curl_dhcp.POSTFIELDS, encode)
    curl_dhcp.setopt(pycurl.WRITEFUNCTION, lambda x: None)
    curl_dhcp.perform()
    curl_dhcp.close
    return

def handle_dhcp_packet(packet):

    # Match DHCP discover
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        #print(packet.summary())
        #print(ls(packet))
        hostname = get_option(packet[DHCP].options, 'hostname')
        text_data_disc = (f"Host {hostname} ({packet[Ether].src}) asked for an IP")
        # Send DHCP discovery data as message to Telegram Bot API with PycURL 
        #text_data_disc = "Host %s (%s) asked for an IP" % (hostname, packet[Ether].src)
        data_disc = {'chat_id': f'{usrchat_id}', 'date': '', 'text': '*** \nNew DHCP Discover \n%s \n***' % (text_data_disc), 'disable_notification': 'false'}
        curl_sendmsg(text_data_disc,data_disc)
        print('---')
        print('New DHCP Discover')
        print(text_data_disc)  

        
    # Match DHCP offer
    elif DHCP in packet and packet[DHCP].options[0][1] == 2:
        #print(packet.summary())
        #print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')
        domain = get_option(packet[DHCP].options, 'domain')

        text_data_offer = (f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
                        f"offered {packet[BOOTP].yiaddr}\n"
                        f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
                        f"{lease_time}, router: {router}, name_server: {name_server}, "
                        f"domain: {domain}")
        # Send DHCP discovery data as message to Telegram Bot API with PycURL 
        #text_data_offer = "DHCP Server %s (%s) offered %s\nDHCP Options: subnet_mask: %s, lease_time: %s, router: %s, name_server: %s, domain: %s" % (packet[IP].src, packet[Ether].src, packet[BOOTP].yiaddr, subnet_mask, lease_time, router, name_server, domain)
        data_offer = {'chat_id': f'{usrchat_id}', 'date': '', 'text': '*** \nNew DHCP Offer \n%s \n***' % (text_data_offer), 'disable_notification': 'false'}
        curl_sendmsg(text_data_disc,data_disc) 
        print('---')
        print('New DHCP Offer')
        print(text_data_offer)

    # Match DHCP request
    elif DHCP in packet and packet[DHCP].options[0][1] == 3:
        #print(packet.summary())
        #print(ls(packet))

        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        text_data_req = (f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}")
        # Send DHCP request data as message to Telegram Bot API with PycURL
        #text_data_req = "Host %s (%s) requested %s" % (hostname, packet[Ether].src, requested_addr)
        data_req = {'chat_id': f'{usrchat_id}', 'date': '', 'text': '*** \nNew DHCP Request \n%s \n***' % (text_data_req), 'disable_notification': 'false'}
        curl_sendmsg(text_data_req,data_req)
        print('---')
        print('New DHCP Request')
        print(text_data_req)
        
    # Match DHCP ack
    elif DHCP in packet and packet[DHCP].options[0][1] == 5:
        print('---')
        print('New DHCP Ack')
        #print(packet.summary())
        #print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"acked {packet[BOOTP].yiaddr}")

        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}")

    # Match DHCP inform
    elif DHCP in packet and packet[DHCP].options[0][1] == 8:
        #print(packet.summary())
        #print(ls(packet))

        hostname = get_option(packet[DHCP].options, 'hostname')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')

        text_data_inform = (f"DHCP Inform from {packet[IP].src} ({packet[Ether].src}) "
              f"hostname: {hostname}, vendor_class_id: {vendor_class_id}")
        # Send DHCP inform data as message to Telegram Bot API with PycURL
        #text_data_inform = "DHCP Inform from %s (%s) hostname: %s, vendor_class_id: %s" % (packet[IP].src, packet[Ether].src, hostname, vendor_class_id)
        data_inform = {'chat_id': f'{usrchat_id}', 'date': '', 'text': '*** \nNew DHCP Inform \n%s \n***' % (text_data_inform), 'disable_notification': 'false'}
        curl_sendmsg(text_data_inform,data_inform)
        print('---')
        print('New DHCP Inform')
        print(text_data_inform)

    else:
        print('---')
        print('Some Other DHCP Packet')
        print(packet.summary())
        print(ls(packet))

    return

if __name__ == "__main__":
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)

