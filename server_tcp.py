#!/usr/bin/python
import time
import os
import threading
import sys
import socket
import fcntl
import struct
from struct import *

scene = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0]
jumping = False
countJump = 0
alive = True
connected = False

server_port = 1098
client_port = 1099

# Game

def game():
    global alive, connected
    last = 0
    cur_draw = ''

    while not connected:
        time.sleep(0.5)

    print 'connecting...'

    time.sleep(1)

    while alive:
        cur_draw = draw()
        send_packet(cur_draw)
        time.sleep(1)

def draw():
    global input, jumping, alive, countJump
    scene_str = "\n"*20
    first = scene.pop(0)
    scene.append(first)
    countJump = countJump - 1 if countJump > 0 else 0

    jumping = countJump > 0

    for (i, e) in enumerate(scene):
        if i == 5 and jumping:
            scene_str += "o"
        else:
            scene_str += " "

    scene_str += "\n"

    for (i, e) in enumerate(scene):
        if(i == 5 and e == 1 and not jumping):
            scene_str += "x"
            alive = False
        elif i == 5 and not jumping:
            scene_str += "o"
        elif e == 0:
            scene_str += "_"
        else:
            scene_str += "|"

    return scene_str

# Send packet
def checksum(msg):
    s = 0
     
    return s

def send_packet(data):
    global server_port, client_port, client_ip, server_ip

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    
    # tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
    # now start constructing the packet
    packet = '';
    
    source_ip, dest_ip  = server_ip, client_ip
    
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
    tcp_source = 1234   # source port
    tcp_dest = client_port   # destination port
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
    global countJump, alive, server_port, client_ip, connected

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

        if dest_port == server_port:        
            data = packet[h_size:]
            if data == 'connect':
                client_ip = s_addr
                print 'connecting with: ' + client_ip 
                connected = True
            elif data == '1':
                countJump = 4

# Helpers
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def runServer():    
    global alive, server_ip, server_port

    server_ip = get_ip_address('eth0')

    print '> Starting server...'
    print '> Server ip: ' + server_ip
    print '> Server port: ' + str(server_port)
    print '> Waiting a connection...'
    try:
        t=threading.Thread(target=game)
        t2=threading.Thread(target=sniffer)
        t.daemon = True
        t.start()
        t2.daemon = True
        t2.start()
    except:
        print "Error: unable to start thread"
    
    while alive:
        pass

    send_packet('0')
    print "\nGAME OVER !!!\n"

if  __name__ =='__main__':runServer()
