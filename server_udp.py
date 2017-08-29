from socket import socket, AF_INET, SOCK_RAW, SOCK_STREAM
from struct import unpack
from binascii import hexlify

HOST = ''              # Endereco IP do Servidor
PORT = 5000            # Porta que o Servidor esta


rawsocket = socket(AF_INET, SOCK_RAW)
rawsocket.bind(("192.168.2.4", 8000))

#udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

orig = (HOST, PORT)
udp.bind(orig)

while True:
	request = rawsocket.recvfrom(2048)
    header = request[0][0:14]
	hd = unpack("!6s6s2s", header)
	
	dest_addr = hexlify(hd[0])
	source_addr = hexlify(hd[1])
	type = hexlify(hd[2])
	
	print "destination: {0}".format(dest_addr)
	print "source: {0}".format(source_addr)
	print "destination: {0}".format(type)
	#msg, cliente = udp.recvfrom(1024)
    print cliente, msg
udp.close()