#!/usr/bin/python
import time
import os
import threading
import sys
import socket
import fcntl
import struct
import binascii
from uuid import getnode as get_mac
from struct import *

clear = lambda: os.system('clear')
client_port = 1099

alive = True

# Keypress
def keypress():
    send_packet('connect')

    while True:
        raw_input()
        send_packet('1')


# Send packet
def checksum(msg):
    s = 0
     
    return s

def send_packet(data):
    global server_port, client_port, client_ip, server_ip,destination_mac

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    
    # tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
    # now start constructing the packet
    packet = '';
    
    source_ip, dest_ip  = client_ip, server_ip

    ##########eth_dest_mac = destination_mac
    ##########eth_sour_mac = get_mac()
    ##########eth_type = int("0x0800", 0) 
    ##########
    ##########ethernet_hdr = pack('!6s62s', eth_dest_mac,eth_sour_mac,eth_type)
    ##########print "ETHERNET FRAME = " + ethernet_hdr

    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321   #Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0    # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    # tcp header fields
    tcp_source = client_port   # source port
    tcp_dest = server_port   # destination port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons (5840)    #   maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
    
    user_data = data
    
    # pseudo header fields
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)
    
    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header + user_data;
    
    tcp_check = sum(map(ord, psh)) #checksum()
    #print tcp_checksum
    
    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
    
    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header + user_data
    
    #Send the packet finally - the port specified has no effect
    s.sendto(packet, (dest_ip , 0 ))

            
# Sniffer
def sniffer():
    global countJump, alive, client_port, server_port,destination_mac

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
 
    # receive a packet
    while alive:
        packet = s.recvfrom(65565)
        
        #packet string from tuple
        packet = packet[0]
        
        #Ethernet Header...
        ethernet_Header=packet[0:14]

        ethrheader=struct.unpack("!6s6s2s",ethernet_Header)
        sourcemac= binascii.hexlify(ethrheader[1])
        
        #take first 20 characters for the ip header
        ip_header = packet[0:20]
        
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        iph_length = ihl * 4
        
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        
        #print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        
        tcp_header = packet[iph_length:iph_length+20]
        
        #now unpack them :)
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        
        source_port = tcph[0]
        dest_port = tcph[1]

        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        
        #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
        
        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size

        if dest_port == client_port:
            destination_mac = sourcemac
            print 'DEST ' + destination_mac       
            data = packet[h_size:]
            clear()
            if data == '0':
                alive = False
            else:
                print data

# Helpers
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def runClient():    
    global alive, client_ip, server_ip, server_port
    
    if len(sys.argv) < 3:
        print 'usage: sudo python client_tcp.py <server_ip> <server_port>'
        sys.exit()

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])

    client_ip = get_ip_address('enp0s3')

    print 'Trying to connect to: ' + server_ip + ':' + str(server_port)

    try:
        t=threading.Thread(target=keypress)
        t2=threading.Thread(target=sniffer)
        t.daemon = True
        t.start()
        t2.daemon = True
        t2.start()
    except:
        print "Error: unable to start thread"
    
    while alive:
        pass
    print "\nGAME OVER !!!\n"

if  __name__ =='__main__':runClient()
