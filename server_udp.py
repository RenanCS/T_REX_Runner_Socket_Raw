import socket
import threading
import struct


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

        self.scene = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0]
        self.jumping = False
        self.countJump = 0
        self.alive = True
        self.countJump = 5
        self.unpacker = struct.Struct('I I')


    def draw(self):

        global input
        scene_str = "\n"*20
        first = self.scene.pop(0)
        self.scene.append(first)
        
        for (i, e) in enumerate(self.scene):

            if self.jumping:
                scene_str += "o"
            else:
                scene_str += " "


        scene_str += "\n"
    
        for (i, e) in enumerate(self.scene):
            
            print(i,self.jumping,self.countJump)

            if self.jumping:
                self.countJump = self.countJump - 1    
        
            if self.countJump == 0:
                self.jumping = False
            
            if(i == 5 and e == 1 and not self.jumping):
                scene_str += "x"
                self.alive = False
            elif i == 5 and not self.jumping:
                scene_str += "o"
            elif e == 0:
                scene_str += "_"
            else:
                scene_str += "|"
            
    
        return scene_str


    def openPackage(self):
        
        print('chegou aqui')

        data = self.sock.recv(1024)

        header = data[0][0:14]    
        ipHeader = data[0][14:34]    
        tcpHeader = data[0][34:54]  

        hd = struct.unpack("!6s6s2s", header)    
        
       
        print('---------- ETHERNET FRAME ----------')    
        print('Destination mac: {0}', hexlify(hd[0]))    
        print('Source mac: {0}', hexlify(hd[1])     )  
        print('Type: {0}', hexlify(hd[2])           )
    
        ip_hrd = struct.unpack("!12s4s4s",ipHeader)    
    
        print('---------- IP ----------'                          )    
        print('Source IP: {0}', socket.inet_ntoa(ip_hrd[1])       )  
        print('Destination IP: {0}', socket.inet_ntoa(ip_hrd[2])  )  
        
        #tcp_hrd = struct.unpack("!HH16s",tcpHeader)    
    
        tcp_hrd = struct.unpack("!HHLLBBHHH",tcpHeader)    
        
        print('---------- TCP ----------'         )   
        print('Source Port: {0}', tcp_hrd[0]      )
        print('Destination Port: {0}', tcp_hrd[1] )   
        print('Flag: {0}',tcp_hrd[2]              )
        print('Acknowledgement : {0}', tcp_hrd[3] )   
        print('TCP header length: {0}',tcp_hrd[4] )

        return


    def listen(self):

        self.sock.listen(5)

        while True:

            client, address = self.sock.accept()

            #self.openPackage()
           
            client.settimeout(20)

            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        
        size = 2048

        while True:

            try:
                data = client.recv(size)

                if data:

                    #print("data chegou", data)

                    if int(data.split(',')[0]) == 1:
                        print("PULO",data.split(',')[0])
                        self.jumping = True;

                    # Set the response to echo back the recieved data 
                    response = self.draw()

                    client.send(response)
                else:
                    raise error('Client disconnected')
                
            except:
                client.close()
                return False


if __name__ == "__main__":
    while True:
        #port_num =  input("Port? ")
        try:
            port_num = 1098 #int(port_num)
            break
        except ValueError:
            pass

    ThreadedServer('',port_num).listen()
