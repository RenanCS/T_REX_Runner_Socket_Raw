# some imports
import socket, sys, time
from struct import *
from binascii import hexlify

def draw(scene):
    clear()
    print 'received draw: ' + scene

def gameloop(action):

    global state,sock
    msg = str(action)

    createPack(msg)

    packet = sock.recvfrom(65565)

    print packet

    readPack(packet)

    return True, draw

def readPack(packet):
    global port_num, destination_mac,source_mac,s_addr,d_addr,tcp_dest

    value_print = ' '
    
    #packet string from tuple
    packet = packet[0]
     
    header = packet[0:14]   
    hd = unpack("!6s 6s 2s", header) 

    destination_mac =  hexlify(hd[0]) 
    source_mac = hexlify(hd[1])
    type_protocol = hexlify(hd[2])

    value_print += '\n' + '---------- ETHERNET FRAME ----------'    
    value_print += '\n' + 'Destination mac: '+  destination_mac
    value_print += '\n' + 'Source mac: '+ source_mac       
    value_print += '\n' + 'Type: '+ type_protocol        

    #take first 20 characters for the ip header
    ip_header = packet[0:20]
     
    # --------------IP HEADER -----------
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
     
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
     
    iph_length = ihl * 4
     
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);

    #Filtra somente protocolo TCP
    if protocol == 6 :
    
        value_print += '\n' + '----------- IP HEADER---------'
        value_print += '\n' + ' Version : ' + str(version) 
        value_print += '\n' + ' IP Header Length : ' + str(ihl) 
        value_print += '\n' + ' TTL : ' + str(ttl) 
        value_print += '\n' + ' Protocol : ' + str(protocol) 
        value_print += '\n' + ' Source Address : ' + str(s_addr) 
        value_print += '\n' + ' Destination Address : ' + str(d_addr)
         
         #-------------- TCP HEADER ------------
        tcp_header = packet[iph_length:iph_length+20]
         
        #now unpack them :)
        tcph = unpack('!HHLLBBHHH' , tcp_header)
         
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4

        value_print += '\n' + '----------- TCP HEADER---------'
        value_print += '\n' + ' Source Port : ' + str(source_port) 
        value_print += '\n' + ' Dest Port : ' + str(dest_port) 
        value_print += '\n' + ' Sequence Number : ' + str(sequence) 
        value_print += '\n' + ' Acknowledgement : ' + str(acknowledgement) 
        value_print += '\n' + ' TCP header length : ' + str(tcph_length)
         
        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size
         
        #get data from the packet
        data = packet[h_size:]
         
        #value_print += '\n' + ' Data : ' + data


        #if int(str(data).split(',')[0]) == 1:
            #print("PULO",data.split(',')[0])
        #    jumping = True;


        if dest_port == port_client:
            print str('>' + data)
            #print value_print
            return True

    return False


 
# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s

def createPack(info):
    
    global sock
    global source_ip,dest_ip
    global port_client, port_server
    
    # now start constructing the packet
    packet = '';
      
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
    tcp_source = port_client   # source port
    tcp_dest = port_server   # destination port
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
     
    user_data = info
     
    # pseudo header fields
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)
     
    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header + user_data;
     
    tcp_check = 0 #checksum(psh)
    #print tcp_checksum
     
    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
     
    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header + user_data
     
    #Send the packet finally - the port specified has no effect
    sock.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target

# def main():    
#     global alive
#     global sock
#     global state, packet
#     global source_ip,dest_ip,tcp_dest 

#     alive = True
#     packet = '';
#     state = 0
      
#     #create a raw socket
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#     except socket.error , msg:
#         print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
#         sys.exit()
 
#     dest_ip = socket.gethostbyname(socket.gethostname())
#     source_ip = '10.0.2.15' #raw_input("Server hostname or ip? ")
#     tcp_dest = 1098 #input("Server port? ")
#     sock.connect((dest_ip, port_server))
    
#     while alive:
#         alive , scene = gameloop(0)
#         draw(scene)

#     print "\nGAME OVER !!!\n"
    


# if  __name__ =='__main__':main()

def runClient():
    global sock, port_client, port_server, source_ip, dest_ip

    source_ip = '10.0.2.15'
    port_server = 1098 #input("Port? ")
    port_client = 1232
    dest_ip = socket.gethostbyname(socket.gethostname())

    print 'starting'

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    print 'socked configured, sending'
     
    sock.connect((dest_ip, port_server))
    createPack('0')

    print 'sent'
    #packet = sock.recvfrom(65565)

    # receive a packet
    last = 0
    while True:    
        packet = sock.recvfrom(65565)

    
        if readPack(packet):
            print 'received'
        
        cur_time = int(round(time.time() * 1000))

        if cur_time % 10000 == 0:
            createPack('1')
        
        if last != cur_time and cur_time % 1000 == 0:
            last = cur_time

if __name__ == "__main__":
    runClient()