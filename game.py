#!/usr/bin/python
import time
import os

clear = lambda: os.system('clear')
scene = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0]

def draw(jumping, dead):
    clear()
    scene_str = "\n"*20
    first = scene.pop(0)
    scene.append(first);
    for (i, e) in enumerate(scene):
        if i == 5 and jumping:
            scene_str += "o"
        else:
            scene_str += " "

    scene_str += "\n"

    for (i, e) in enumerate(scene):
        if(i == 5 and e == 1 and not jumping):
            scene_str += "x"
            dead = True
        elif i == 5 and not jumping:
            scene_str += "o"
        elif e == 0:
            scene_str += "_"
        else:
            scene_str += "|"

    print scene_str
    return dead

def main():
    jumping = False
    dead = False

    while not dead:
        dead = draw(jumping, dead)
        time.sleep(0.2)
    print "\nGAME OVER !!!\n"


if  __name__ =='__main__':main()
