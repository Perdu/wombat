#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Dependencies :
# - python2.7
# - python-pcapy (debian) / python2-pcapy (archlinux)
# - python-netifaces (debian) / python2-netifaces (archlinux)

# todo :
# - check that interface exists
# - check that interface is in monitor mode
# - check that memory usage is constant

import datetime
import pcapy
import sys
from struct import *
import threading
import socket
import time
import json
import os
import base64
import string
import netifaces
import re
import logging
from logging.handlers import RotatingFileHandler

with open("/etc/wombat/node_config.json") as config_file:
    config = json.load(config_file)

iface = config["iface"]
SERVER_IP = config["server_ip"]
SERVER_PORT = config["server_port"]
USE_DATE_SYNC = bool(config["use_date_sync"])
DATE_SYNC_PORT = config["date_sync_port"]
try:
    CAPTURE_PROBES_ONLY = config["capture_probes_only"]
except KeyError:
    CAPTURE_PROBES_ONLY = True
NODE_MAC = ''
DATE_FORMAT = '%F %H:%M:%S %z'
LOG_FILE = str(config["log_file"])

MAX_TIME_DIFF_BURST = 100000 #µs
current_bursts = {}
finished_bursts = []
time_synchronized = False
logger = None

class Frame:
    time = ""
    rssi = 0
    ssid = ''
    def __init__(self, time, rssi, ssid):
        self.time = time
        self.rssi = rssi
        self.ssid = ssid
        filter(lambda x: x in set(string.printable), self.ssid) # remove non-printable characters

class Burst:
    mac_address = ""
    timestamp = 0
    nb_frames = 0
    best_rssi = 0
    ssids = set()
    def __init__(self, mac_address, timestamp, nb_frames, best_rssi, ssids):
        self.mac_address = mac_address
        self.timestamp = timestamp
        self.nb_frames = nb_frames
        self.best_rssi = best_rssi
        self.ssids = ssids
    def __repr__(self):
        ssid_str = ''
        ssids = list(self.ssids)
        ssid_str = ssids[0]
        for ssid in ssids[1:]:
            ssid_str += ',' + str(ssid).replace(',', '\,')
        return self.mac_address + ',' + str(printable_time(self.timestamp)) + ',' + str(int(round(self.best_rssi))) + ',' + str(self.nb_frames) + ',' + base64.b64encode(ssid_str)

def printable_time(timestamp):
    return datetime.datetime.fromtimestamp(timestamp/1000000.0).strftime('%d %b %y %H:%M:%S:%f')

def report_bursts():
    while 1:
        #list() avoids RunTimeError when the dict is modified during iteration
        for m in list(current_bursts):
            current_time = time.time() * 1000000
            if current_time - current_bursts[m][0].time > MAX_TIME_DIFF_BURST:
                logger.info("Finished burst: %s" % current_bursts[m][0].time)
                logger.debug(m)
                handle_finished_burst(m)
        ok = True
        while finished_bursts != []:
            if ok:
                b = finished_bursts.pop()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((SERVER_IP, SERVER_PORT))
                s.send(str(NODE_MAC) + ',' + str(b))
                s.close()
                #logger.debug(str(NODE_MAC) + ',' + str(b))
                ok = True
            except:
                ok = False
                logger.warning("Failed joining server")
                time.sleep(2)
        time.sleep(2)

# convert a string of 6 characters of ethernet address into a dash separated
# hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

def handle_finished_burst(mac_address):
    rssis = [x.rssi for x in current_bursts[mac_address]]
    ssids = set([x.ssid for x in current_bursts[mac_address]])
    best_rssi = max(rssis)
    b = Burst(mac_address,
              current_bursts[mac_address][0].time,
              len(current_bursts[mac_address]),
              best_rssi,
              ssids)
    finished_bursts.append(b)
    del current_bursts[mac_address]

def parse_packet(packet, header):
    try:
        header_length = int(packet[2].encode('hex'), 16) # 3rd byte
        probe = packet[header_length:]
        mac_address = eth_addr(probe[10:16])
        # Radiotap headers are complicated to parse, so we use the position of
        # the RSSI in some Wi-Fi dongles:
        # - TP-Link TL-WN722N
        rssi_hex = packet[header_length - 2].encode('hex')
        # - Wi-Pi
        if int(rssi_hex, 16) == 0:
            rssi_hex = packet[14].encode('hex')
        rssi = int(rssi_hex, 16) - 256
        time = header.getts()[0] * 1000000 + header.getts()[1]
        probe_data = probe[24:]
        ssid = ''
        # test if frame is a probe request
        if probe[0].encode('hex') == '40' and probe_data[0].encode('hex') == '00':
            ssid_length = int(probe_data[1].encode('hex'), 16)
            ssid = probe_data[2:2+ssid_length]
        f = Frame(time, rssi, ssid)
        if mac_address in current_bursts:
            if time - current_bursts[mac_address][-1].time > MAX_TIME_DIFF_BURST:
                handle_finished_burst(mac_address)
                current_bursts[mac_address] = [f]
            else:
                current_bursts[mac_address].append(f)
        else:
            current_bursts[mac_address] = [f]
        logger.debug("%s,%s,%s,%s" % (mac_address, rssi, printable_time(time), ssid))
    except:
        logger.error("Error: Frame could not be parsed")

def open_iface(iface):
    ok = False
    while not ok:
        try:
            os.system('sudo ifconfig %s up' % iface)
            cap = pcapy.open_live(iface , 65536 , 1 , 0)
            if CAPTURE_PROBES_ONLY:
                cap.setfilter('wlan type mgt subtype probe-req')
            else:
                cap.setfilter('wlan type mgt subtype probe-req || wlan type data || wlan type ctl subtype ps-poll')
            ok = True
        except pcapy.PcapError as e:
            logger.warning("Unable to bring interface %s up, retrying in 1s..." % iface)
            logger.error("Error: %s" % e)
            time.sleep(1)
    logger.info("Interface %s up." % iface)
    return cap

def sync_time():
    global time_synchronized
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, DATE_SYNC_PORT))
        s.send('sync plz')
    except:
        logger.warning("Failed joining server")
        return
    try:
        date = s.recv(1024)
        if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', date):
            logger.info("Setting time to %s" % date)
            os.system("sudo date -s '" + date + "' '+" + DATE_FORMAT + "'")
            time_synchronized = True
        else:
            logger.error("Unrecognized time format")
    except Exception as e:
        logger.error("Failed setting time: " + str(e))

def create_rotating_log(path):
    global logger
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.INFO)
    # set to 100 Mo
    handler = RotatingFileHandler(path, maxBytes=100*1000*1000, backupCount=3)
    logger.addHandler(handler)

def main(argv):
    global NODE_MAC
    global time_synchronized
    create_rotating_log(LOG_FILE)
    #sys.stdout = open(LOG_FILE, 'wb', buffering=0)
    if USE_DATE_SYNC:
        sync_time()
        while not time_synchronized:
            logger.info("Waiting for time synchronization")
            time.sleep(10)
            sync_time()
    else:
        while os.system('ntptime | grep ERROR') != 256:
            logger.info("Waiting for NTP to synchronize time")
            time.sleep(1) # Wait for ntp to sync date correctly
    ok = False
    while not ok:
        try:
            NODE_MAC = netifaces.ifaddresses('eth0')[netifaces.AF_LINK][0]['addr']
            ok = True
        except:
            logger.info("Interface eth0 not available yet")
            time.sleep(1)
    logger.debug("eth0 is up")
    cap = open_iface(iface)
    report_thread = threading.Thread(target=report_bursts)
    report_thread.setDaemon(True)
    report_thread.start()
    logger.debug("Starting capture")
    while(1):
        try:
            (header, packet) = cap.next()
            parse_packet(packet, header)
        except pcapy.PcapError:
            logger.error('Interface went down, waiting and trying to bring it up again...')
            time.sleep(1)
            cap = open_iface(iface)
        except socket.timeout:
            continue

if __name__ == "__main__":
    main(sys.argv)
