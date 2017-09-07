#!/usr/bin/python
import socket
import time
import os
import threading
import sys

clear = lambda: os.system('clear')
alive = True
scene = ''

def draw(scene):
    clear()
    print 'received draw: ' + scene

def gameLoop():
    global alive, scene
    alive = True
    while alive:
        alive, scene = getSetDataServer(0)    
        draw(scene)
        time.sleep(0.2)

def readKeypress():
    global alive
    while alive:
        raw_input()
        alive, scene = getSetDataServer(1)
        sendServerData()

def getSetDataServer(action):
    
    global state

    msg = str(action) + ',' +  str(state)

    state += 1
    
    sock.send(msg)
    
    draw = sock.recv(1024)
    
    return True, draw

    #return True, '---'

def sendServerData():
    sock.send(1)
    # send the jump to server
    print 'sent jump'

def main():    
    global alive
    global sock
    global state 

    state = 0
       
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = 'localhost' #raw_input("Server hostname or ip? ")
    port = 1096 #input("Server port? ")
    #sock.connect((host,port))

    sock.connect(('127.0.0.1', 1098))
        
    try:
        t=threading.Thread(target=gameLoop)
        t2=threading.Thread(target=readKeypress)
        t.daemon = True
        t.start()
        t2.daemon = True
        t2.start()
    except:
        print "Error: unable to start thread"
    
    while alive:
        pass
    print "\nGAME OVER !!!\n"
    

if  __name__ =='__main__':main()



'''
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = 'localhost' #raw_input("Server hostname or ip? ")
port = 1096 #input("Server port? ")
#sock.connect((host,port))

sock.connect(('127.0.0.1', 1098))

while True:
    data = raw_input("message: ")
    sock.send(data)
    print "response: ", sock.recv(1024)

'''