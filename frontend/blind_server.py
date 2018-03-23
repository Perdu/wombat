#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import sys
import json
import draw_timeline
import SocketServer
import threading
import time
import ast
from datetime import datetime, timedelta
from Tkinter import *
import PIL
from PIL import Image, ImageTk # debian: python-pil.imagetk

HOST = '0.0.0.0'
PORT = 4003
MAX_TIME_BURST = 500
prev_time = datetime.now()
prev_fig = None
gui = None

def to_milliseconds(d):
    return d.days * 86400000 + d.seconds * 1000 + d.microseconds / 1000

class MyTCPQueryHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        global prev_time
        global prev_fig
        # ast.literal_eval is safe: it only interprets data structure
        now = datetime.now()
        time_diff = to_milliseconds(now - prev_time)
        prev_time = now
        if abs(time_diff) < MAX_TIME_BURST:
            print "Ignoring probe from same burst"
            return
        new_data = self.request.recv(1024)
        self.data = ""
        while new_data:
            self.data += new_data
            new_data = self.request.recv(1024)
        if self.data == "No info on device":
            print self.data
        else:
            self.data = ast.literal_eval(self.data)
            image = draw_timeline.draw_figure(self.data, draw_image=False)
            tkimage = ImageTk.PhotoImage(image)
            gui.change_image(tkimage)

def exit_program():
    gui.win.destroy()
    gui.win.quit()

def draw_GUI():
    global gui
    gui = GUI()
    gui.win.mainloop()

class GUI():
    btn_close = None
    def __init__(self):
        self.win = Tk()
        self.height = 1300
        self.width = 700
        self.display_wombat()
        self.prev_photo_time = datetime.now()
        self.win.protocol("WM_DELETE_WINDOW", exit_program)

    def display_wombat(self):
        self.image = Image.open("wombat.png")
        basewidth = self.height
        wpercent = (basewidth / float(self.image.size[0]))
        hsize = int((float(self.image.size[1]) * float(wpercent)))
        self.image = self.image.resize((basewidth, hsize), PIL.Image.ANTIALIAS)
        self.photo = ImageTk.PhotoImage(self.image)
        self.display_photo()
        self.photo_displayed = False

    def display_photo(self):
        self.panel = Label(self.win, image=self.photo)
        self.panel.grid(row=0, column=2, sticky=E)

    def change_image(self, fig):
        self.panel.destroy()
        self.photo = fig
        self.display_photo()
        self.prev_photo_time = datetime.now()
        self.photo_displayed = True

def image_close():
    while gui is None:
        print "Waiting for GUI to be initialized"
        time.sleep(1)
    while True:
        time.sleep(1)
        if gui.photo_displayed and ((datetime.now() - gui.prev_photo_time) > timedelta(seconds=30) or (gui.prev_photo_time - datetime.now() < timedelta(seconds=-30))):
            gui.panel.destroy()
            gui.display_wombat()
            gui.prev_photo_time = datetime.now()

if __name__ == "__main__":
    server = SocketServer.TCPServer((HOST, PORT), MyTCPQueryHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.setDaemon(True)
    server_thread.start()
    server_image_close = threading.Thread(target=image_close)
    server_image_close.setDaemon(True)
    server_image_close.start()
    draw_GUI()
