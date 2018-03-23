#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import json
import socket
#import SocketServer
import threading
import subprocess
import re
import time
import os

# loading optoutAP config 

with open("/etc/wombat/optoutAP_config.json") as config_file:
    config = json.load(config_file)

HOSTAPD_CONFIG_FILE=config["hostapd_config_file"]
SERVER_IP=config["server_ip"]
SERVER_OPTOUT_PORT=config["server_port"]
REDUCE_TXPOWER=bool(config["reduced_signal_strength"])

auth_regexp = re.compile(r"wlan\d*: .*STA [\da-f:]* .*IEEE 802.11: authenticated.*")

def send_id_to_server(id):
    print "sending id to server: " + id
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_OPTOUT_PORT))
        print "Connected to server"
        s.send(id)
    except Exception as e: 
        print "Failed joining server"
        print e
        return

def handle_auth_request(r):
    print "auth_regexp:"
    print r
    id = r.split(' ')[2].strip()
    print "id: [",id,"]"
    send_id_to_server(id)

def handle_line(l):
    if auth_regexp.match(l):
        handle_auth_request(l)    

if __name__ == "__main__":
    bashCommand = "sudo stdbuf -i0 -o0 -e0 hostapd " + HOSTAPD_CONFIG_FILE
    print bashCommand
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE )
    if REDUCE_TXPOWER:
        time.sleep(5)
        os.system('sudo iwconfig wlan0 txpower 1')
    for l in iter(lambda: process.stdout.readline(), ''):
        print  l,
        handle_line(l)
