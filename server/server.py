#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import json
from datetime import datetime, date, time, timedelta
import time
import itertools
import SocketServer
import threading
from threading import Thread
import base64
import os
import pcapy
import socket
import re
import sys
import logging
from logging.handlers import RotatingFileHandler

# loading server config 
with open("/etc/wombat/server_config.json") as config_file:
    config = json.load(config_file)

PRODUCTION = bool(config["system_params"]["production"])
REPORT_SERVER_PORT = config["server_params"]["reporting_port"]
#REPORT_LOG_FILE = str(config["server_params"]["report_log_file"])
LOG_FILE = str(config["server_params"]["log_file"])
BLACK_LIST_FILE = str(config["server_params"]["black_list_file"])
WHITE_LIST_FILE = str(config["server_params"]["white_list_file"])
QUERY_SERVER_PORT = config["server_params"]["querying_port"]
QUERY_SERVER_TIMELINE_RESOLUTION =  config["server_params"]["query_server_timeline_resolution"] # in minutes
DEVICE_EXPIRY_DELAY = config["server_params"]["device_expiry_delay"] # in seconds
CHECK_REPORT_DELTATIME = config["server_params"]["check_report_deltatime"]
REPORT_DELTATIME_TOLERANCE =  config["server_params"]["report_deltatime_tolerance"] # in seconds
TOPOLOGY_FILE = config["system_params"]["topology_file"] 
OUI_FILE = config["server_params"]["OUI_file"]
OPTOUT_SERVER_PORT = config["server_params"]["optout_port"]
STATS_TIME_WINDOW = int(config["server_params"]["stats_time_window"])
NODES_RSSI_THRESHOLD = int(config["server_params"]["nodes_rssi_threshold"])
MIN_APPARITION_LENGTH = int(config["server_params"]["min_apparition_length"])
MAX_BURST_DURATION = int(config["server_params"]["max_burst_duration"])
BATCH_SIZE = int(config["server_params"]["batch_size"])



BLIND_MODE = bool(config["blind_mode"]["blind_mode"])
USING_SENSOR = bool(config["blind_mode"]["using_sensor"])
SENSOR_WINDOW_SECONDS = int(config["blind_mode"]["sensor_window_seconds"])
MONITOR_IFACE = config["blind_mode"]["interface"]
FRONTEND_IP = config["blind_mode"]["frontend_ip"]
RSSI_DETECTION_THRESHOLD = config["blind_mode"]["rssi_detection_threshold"]
FRONTEND_PORT = config["blind_mode"]["frontend_port"]

USE_DATE_SYNC = bool(config["date_sync"]["use_date_sync"])
DATE_FRONTEND_PORT = config["date_sync"]["frontend_port"]
NODE_PORT = config["date_sync"]["node_port"]

BLACKLIST_SSID = config["system_params"]["blacklist_ssid"]
BLACKLIST_EXPIRY_DELAY =  config["system_params"]["blacklist_expiry_delay"]
DATE_FORMAT = '%F %H:%M:%S %z'
time_synchronized = False
logger = None



# loading system topology
with open(TOPOLOGY_FILE) as topology_file:    
    topology = json.load(topology_file)
NODES = dict((el["id"],el) for el in topology["nodes"])
print NODES
ZONES = dict((el["id"],el) for el in topology["zones"])
print ZONES
#reportlogs = open(REPORT_LOG_FILE, 'ab+', 0)

device_list = {}
blacklist = []
expiring_blacklist = []
OUIs = {}
reportfilter = None
last_seen_devices = ["No device seen"]
last_seen_dates = [datetime.now()]
last_seen_rssis = [-1000]
nodes = {}
optout_ok = False

class Node():
    def __init__(self, ip, last_seen):
        self.ip = ip
        self.last_seen = last_seen

#load OUIs
with open(OUI_FILE, 'r') as oui_file:
    for l in oui_file:
        infos = l.split("(hex)")
        mac = infos[0].strip().replace("-", ":").lower()
        vendor = infos[1].strip()
        OUIs[mac] = vendor

def get_expiring_blacklist_set():
    bl = set()
    for rep in expiring_blacklist:
        bl.add(rep[0])
    return bl

def is_random_mac(raw_mac):
    mac = raw_mac[0:2].decode("hex") + raw_mac[3:5].decode("hex") + raw_mac[6:8].decode("hex")
    mac_nb = [ord(c) for c in mac]
    return (mac_nb[0] & 0x02 == 2)

class ReportFilter(object):
    def __init__(self):
        self.whitelist = []

    def add_to_expiring_black_list(self,device_id):
        now =  datetime.now()
        expiring_blacklist.append([device_id,now])
        # Delete all data about device
        if device_id in device_list:
            del device_list[device_id]

    def load_black_list(self,bl_file):
        global blacklist
        blacklist = self.load_file(bl_file)

    def load_white_list(self,wl_file):
        self.whitelist = self.load_file(wl_file)

    def load_file(self,file_name):
        l = []           
        with open(file_name) as fp:
            for line in fp:
                line = line.strip("\n")
                l += [line]
        return l

    def keep(self,device_id,time):
        return self.ok_time(time) and not self.filtered_device(device_id)
    
    def ok_time(self, time):
        if not CHECK_REPORT_DELTATIME: 
            return True
        now =  datetime.now()
        delta = time - now
        if abs(delta.total_seconds())>REPORT_DELTATIME_TOLERANCE:
            logger.warning("Report time too far from local time: %s, %s, %s" % (time, now, delta))
            return False
        else:
            return True
        
    def filtered_device(self,device_id):
        if device_id in get_expiring_blacklist_set():
            return True
        if self.whitelist:
            return (device_id not in self.whitelist)
        elif blacklist:
            return (device_id in blacklist)
        return False

class Report(object):
    def __init__(self, time, sensor_id, rssi, nb_frame):
        #(time_string, sensor_id, rssi, nb_frame) = report_string.split(',')
        self.time =  datetime.strptime(time, "%d %b %y %H:%M:%S:%f")  
        self.sensor_id = sensor_id
        self.rssi = float(rssi)
        self.nb_frame = int(nb_frame)
    def __repr__(self):
        return '{0}, {1}, {2}, {3}'.format(self.time, self.sensor_id,self.rssi,self.nb_frame)
    def get_time_interval(self):
        d = self.time
        k = d + timedelta(minutes=-(d.minute % QUERY_SERVER_TIMELINE_RESOLUTION)) 
        res =  datetime(k.year, k.month, k.day, k.hour, k.minute, 0)
        return res

class Burst(object):
    def __init__(self):
        self.reports = []
    def __repr__(self):
        return self.reports[0]
    def add_report(self,report):
        self.reports.append(report)
    def get_start_time(self):        
        try:
            return sorted(self.reports,key=lambda report: report.time)[0].time
        except IndexError:
            return datetime.fromtimestamp(0)

        
class DeviceInfo(object):
    def __init__(self, device_id):
        self.device_id = device_id
        self.vendor_name = self.resolve_oui(device_id)
        self.reports = []         
        self.ssids = {}
        self.random_mac_address = is_random_mac(device_id)

    def add_ssids(self, ssids):
        s = base64.b64decode(ssids)
        for ssid in s.split(','):
            if ssid:
                self.ssids[ssid] =  self.ssids.get(ssid,0) +1
                if ssid == BLACKLIST_SSID:
                    logger.debug("Adding device %s to the expiring blacklist" % str(self.device_id))
                    reportfilter.add_to_expiring_black_list(self.device_id)
        
    def add_report(self, time_string, sensor_id, rssi, nb_frame,ssids):
        report = Report(time_string, sensor_id, rssi, nb_frame)
        self.last_seen = report.time
        self.reports.append(report)
        self.add_ssids(ssids)

    def __repr__(self):
        string = str(self.device_id) 
        string += str(self.reports)
        return string

    def resolve_oui(self,device_id):
        oui = device_id[:8]
        if oui in OUIs:
            return OUIs[oui]
        else:
            return "unknown"

    def summary(self):
        summary = self.create_summary()
        return summary

    def get_apparition_length(self):
        self.update_times()
        return (self.last_seen - self.first_seen).total_seconds()

    def create_summary(self):
        summary = {}
        self.update_timeline()
        self.update_times()
        self.update_stats()
        summary['timeline'] = self.synthetic_timeline
        summary['device_id'] = self.device_id
        summary['vendor_name'] = self.vendor_name
        summary['ssids'] = list(self.ssids.keys())
        summary['total_nb_frames'] = self.total_nb_frames
        summary['first_seen'] = self.first_seen.strftime("%d %b %y %H:%M:%S")
        summary['last_seen'] = self.last_seen.strftime("%d %b %y %H:%M:%S")
        summary['random_mac_address'] = self.random_mac_address
        return summary

    def update_stats(self):
        total = sum(int(report.nb_frame) for report in self.reports)
        self.total_nb_frames = total

        
    def update_times(self):
        self.first_seen = sorted(self.reports,key=lambda report: report.time)[0].time
        self.last_seen = sorted(self.reports,key=lambda report: report.time)[-1].time

    def update_timeline(self):
        self.timeline = self.create_timeline()
        self.synthetic_timeline = self.create_synthetic_timeline()

    def get_last_zone(self, stats_time_window):
        self.update_timeline()
        g = sorted(self.reports,key=lambda report: report.time)
        if self.synthetic_timeline == None:
            return None
        last_timezone = self.synthetic_timeline[-1]
        if abs((datetime.now() - datetime.strptime(last_timezone[1], "%d %b %y %H:%M")).total_seconds()) < stats_time_window:
            return last_timezone[2]
        else:
            return None

    def create_synthetic_timeline(self):
        if self.timeline == []:
            return None
        l = self.timeline
        synth_timeline = []
        current_area = -1
        current_start = ''
        for item in l:
            if item[1] != current_area:
                if current_area != -1:
                    new_interval = [current_start,item[0],current_area]
                    synth_timeline += [new_interval]
                current_area = item[1]
                current_start = item[0]

        new_interval = [current_start,l[-1][0],l[-1][1]]
        synth_timeline += [new_interval]
        return synth_timeline

    def group_by_burst(self, reports):
        bursts = []
        cur_burst = Burst()
        for r in reports :
            if (r.time - cur_burst.get_start_time()).total_seconds() < MAX_BURST_DURATION :
                cur_burst.add_report(r)
            else :
                if len(cur_burst.reports) > 0 :
                    bursts.append(cur_burst)
                cur_burst =  Burst()
                cur_burst.add_report(r)
        if len(cur_burst.reports) > 0 :
            bursts.append(cur_burst)
        return bursts

    def choose_area(self, batch):
        reports = []
        # put all the report of this batch in a single array
        for burst in batch:
            for r in burst.reports :
                reports.append(r)
        # search for the area  
        # based on the best rssi over the batch
        reports.sort(key = lambda x: x.rssi)
        return reports[-1].sensor_id   
    
    def create_timeline(self):
        timeline = []
        self.reports.sort(key = lambda x: x.time)
        bursts = self.group_by_burst(self.reports)

        # group bursts by set (batch) of BATCH_SIZE
        batchs = []
        cur_batch = []
        i = 0
        for burst in bursts :
            cur_batch.append(burst)
            if i% BATCH_SIZE ==0:
                batchs.append(cur_batch)
                cur_batch = []
            i+=1
        if len(cur_batch) > 0 :
            batchs.append(cur_batch)

        # create the timeline by choosing the area for each batch
        for batch in batchs :
            sensor_id = self.choose_area(batch) # choose the area
            t = batch[0].get_start_time() # reference time is the time of the first burst of the batch
            timeline += [[t.strftime("%d %b %y %H:%M"), ZONES[NODES[sensor_id]["zone_id"]]["name"]]]
        return timeline
     
    # def create_timeline(self):
    #     g = groupby(sorted(self.reports,key=lambda report: report.time), key=Report.get_time_interval)
    #     timeline = []
    #     for key, items in g:
    #         nb_times_seen = {}
    #         nb_frames = {}
    #         best_rssi = {}
    #         for item in items:
    #             if item.sensor_id not in NODES:
    #                 logger.error("Error: sensor %s not defined in the topology file" % item.sensor_id)
    #             else:
    #                 area_id = NODES[item.sensor_id]["zone_id"]
    #                 nb_times_seen[area_id] = nb_times_seen.get(area_id,0) + 1
    #                 nb_frames[area_id] = nb_frames.get(area_id,0) + item.nb_frame 
    #                 best_rssi[area_id] = max(item.rssi,best_rssi.get(area_id,-100) )
    #         #selected_area_id = max(nb_frames, key=nb_frames.get) # select area based on number of received frames
    #         if nb_times_seen != {}:
    #             #selected_area_id = max(nb_times_seen, key=nb_frames.get) # select area based on number of reports
    #             selected_area_id = max(best_rssi, key=best_rssi.get) # select area based on best rssi
    #             timeline += [[key.strftime("%d %b %y %H:%M"), ZONES[selected_area_id]["name"]]]
    #     return timeline

class MyTCPReportHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server for the report server
    """
    def handle(self):
        global nodes
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        sensor_id, device_id, time_string, rssi, nb_frame, ssids = self.data.split(',')
        if sensor_id in nodes:
            nodes[sensor_id].last_seen = time_string
        else:
            nodes[sensor_id] = Node(self.client_address[0], time_string)
        logger.info("Received report from " + self.client_address[0] + " with timestamp " + time_string)
        log_msg = "{} wrote: ".format(self.client_address[0]) + self.data
        if int(rssi) < NODES_RSSI_THRESHOLD:
            log_msg = log_msg + " (discarding)"
            return
        logger.debug(log_msg)
        time = datetime.strptime(time_string, "%d %b %y %H:%M:%S:%f")
        if reportfilter.keep(device_id,time):
            device_list.setdefault(device_id,DeviceInfo(device_id)).add_report(time_string, sensor_id, rssi, nb_frame,ssids)
            #reportlogs.write(self.data)
            #reportlogs.write("\n")
            #reportlogs.flush()
        else:
            logger.debug("ReportFilter: discarding: %s" % device_id)

class MyTCPOptOutHandler(SocketServer.BaseRequestHandler):
    """
    The OptoutHandler class for our server 
    """
    def handle(self):
        global optout_ok
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        logger.info("Optout {} wrote:".format(self.client_address[0]))
        device_id = str(self.data)
        logger.debug(device_id)
        if re.match(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', device_id):
            logger.debug("Adding device to expiring blacklist: %s" % device_id)
            reportfilter.add_to_expiring_black_list(device_id)
            optout_ok = datetime.now().strftime("%d %b %y %H:%M:%S")
        else: 
            logger.error("Invalid identifier %s" % device_id)
            # TODO

class MyTCPQueryHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for the query server
    """
    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        if USE_DATE_SYNC and not time_synchronized:
            j = {"message": "Time not synchronized", "port": DATE_FRONTEND_PORT}
            self.request.sendall(json.dumps(j))
        else:
            if not PRODUCTION and self.data == "all":
                dic = {"devices": device_list.keys()}
                dic["message"] = ""
                j = json.dumps(dic)
                self.request.sendall(j)
            elif self.data == 'stats':
                dic = {}
                zones = {}
                for dev in list(device_list):
                    if is_random_mac(dev) or device_list[dev].vendor_name == "unknown" or device_list[dev].get_apparition_length() < MIN_APPARITION_LENGTH:
                        continue
                    try:
                        zone = device_list[dev].get_last_zone(STATS_TIME_WINDOW)
                        if zone is not None:
                            if zone in zones:
                                zones[zone] += 1
                            else:
                                zones[zone] = 1
                    except KeyError, e:
                        logger.error("Missing device in topology file: %s" % e)
                dic["devices_by_zone"] = zones
                dic["message"] = ""
                dic["nb_blacklisted_devices"] = len(expiring_blacklist) + len(blacklist)
                j = json.dumps(dic)
                self.request.sendall(j)
            elif self.data == 'nodes':
                d = {"message": "", "nodes": {}}
                for mac in nodes.keys():
                    ans = nodes[mac].ip
                    if mac in NODES:
                        ans += ' (%s)' % NODES[mac]["name"]
                    else:
                        ans += ' (nouveau)'
                    ans += ' last report: %s' % nodes[mac].last_seen
                    d["nodes"][mac] = ans
                if optout_ok != False:
                    d["nodes"]["optout"] = "last_seen: " + optout_ok # contains time string
                self.request.sendall(json.dumps(d))
            else:
                device_id = str(self.data)
                if device_id in device_list:
                    info = device_list[device_id]
                    summary = info.summary()
                    summary["message"] = ""
                    j = json.dumps(summary)
                    self.request.sendall(j)
                elif device_id in blacklist or device_id in get_expiring_blacklist_set():
                    logger.info("Received query for blacklisted device")
                    logger.debug(str(self.data))
                    self.request.sendall("blacklisted")
                else:
                    logger.info("Received query for unknown device %s" % str(self.data))
                    self.request.sendall("unknown")

class TCPSensorHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        if USE_DATE_SYNC and not time_synchronized:
            j = {"message": "Time not synchronized", "port": DATE_FRONTEND_PORT}
            self.request.sendall(json.dumps(j))
        else:
            self.data = self.request.recv(1024).strip()
            logger.info("{} wrote:".format(self.client_address[0]) + self.data)
            if self.data == "device seen":
                # Uncomment to force waiting upon request reception
                #time.sleep(SENSOR_WINDOW_SECONDS)
                now = datetime.now()
                dev = self.find_biggest_rssi(now)
                if dev is not None:
                    if dev in get_expiring_blacklist_set() or dev in blacklist:
                        self.request.sendall("blacklisted")
                    elif dev not in device_list:
                        self.request.sendall("unknown")
                    else:
                        self.request.sendall(json.dumps(device_list[dev].summary()))
                else:
                    self.request.sendall("No device seen")

    def find_biggest_rssi(self, now):
        global last_seen_devices
        global last_seen_dates
        global last_seen_rssis
        # clear old detections
        finished = False
        while len(last_seen_dates) > 0 and not finished:
            time_diff = (now - last_seen_dates[0]).total_seconds()
            if time_diff > SENSOR_WINDOW_SECONDS or time_diff < -SENSOR_WINDOW_SECONDS:
                last_seen_dates.pop(0)
                last_seen_devices.pop(0)
                last_seen_rssis.pop(0)
            else:
                finished = True
        max_rssi = -1000
        max_rssi_device = None
        for i in range(len(last_seen_rssis)):
            if last_seen_rssis[i] > max_rssi:
                max_rssi = last_seen_rssis[i]
                max_rssi_device = last_seen_devices[i]
        logger.debug("Returning device with rssi %s : %s" % (max_rssi, max_rssi_device))
        return max_rssi_device

class date_frontend_handler(SocketServer.BaseRequestHandler):
    def handle(self):
        global time_synchronized
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', self.data):
            logger.info("Setting time to %s" % self.data)
            os.system("sudo date -s '" + self.data + "' '+" + DATE_FORMAT + "'")
            time_synchronized = True
            self.request.sendall("ok")

class date_node_handler(SocketServer.BaseRequestHandler):
    def handle(self):
        # self.request is the TCP socket connected to the client
        logger.debug(self.client_address)
        if time_synchronized:
            curtime = time.strftime(DATE_FORMAT, time.gmtime())
            self.request.sendall(curtime)

def delete_expired_devices():
    # Delete expired devices 
    # run every DEVICE_EXPIRY_DELAY
    now = datetime.now()
    for k, v in device_list.items():
        delta = (v.last_seen - now).total_seconds()
        if abs(delta)  >  DEVICE_EXPIRY_DELAY:
            logger.debug('%s is expired: deleting' % k)
            del device_list[k]            
    threading.Timer(DEVICE_EXPIRY_DELAY, delete_expired_devices).start()



def delete_expired_blacklist():
    # Delete expired elements in the blacklist
    now = datetime.now()
    for v in expiring_blacklist:
        delta = (v[1] - now).total_seconds()
        if abs(delta)  >  BLACKLIST_EXPIRY_DELAY:
            logger.debug('%s is expired: deleting' % v)
            expiring_blacklist.remove(v)            
    threading.Timer(BLACKLIST_EXPIRY_DELAY, delete_expired_blacklist).start()

def open_iface(iface):
    ok = False
    while not ok:
        try:
            os.system('sudo ifconfig %s down && sudo iwconfig %s mode monitor && sudo ifconfig %s up' % (iface, iface, iface))
            cap = pcapy.open_live(iface , 65536 , 1 , 0)
            cap.setfilter('wlan type mgt subtype probe-req')
            ok = True
        except pcapy.PcapError:
            logger.error("Unable to bring interface %s up, retrying in 1s... Are you root?" % iface)
            time.sleep(1)
    logger.info("Interface %s up." % iface)
    return cap

# convert a string of 6 characters of ethernet address into a dash separated
# hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

def detect_close_device(packet, header):
    global last_seen_device
    global last_seen_date
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
    except:
        logger.error("Error: Frame could not be parsed")
        return
    logger.debug("rssi: %s %s" % (rssi, mac_address))
    if rssi > RSSI_DETECTION_THRESHOLD:
        if USING_SENSOR:
            last_seen_device = mac_address
            last_seen_dates.append(datetime.now())
            last_seen_devices.append(last_seen_device)
            last_seen_rssis.append(rssi)
        else:
            try:
                logger.debug("Sending info to frontend")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((FRONTEND_IP, FRONTEND_PORT))
                if mac_address in device_list:
                    info = device_list[mac_address]
                    s.send(str(info.summary()))
                else:
                    s.send("No info on device")
                logger.debug("Info sent to frontend")
            except socket.error:
                logger.error("Failed joining frontend")

def create_rotating_log(path):
    global logger
    logger = logging.getLogger("Rotating Log")
    if PRODUCTION:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)
    # set to 100 Mo
    handler = RotatingFileHandler(path, maxBytes=100*1000*1000, backupCount=3)
    logger.addHandler(handler)

def to_milliseconds(d):
        return d.days * 86400000 + d.seconds * 1000 + d.microseconds / 1000

if __name__ == "__main__":
    create_rotating_log(LOG_FILE)
    logger.info(datetime.now().strftime("%d %b %y %H:%M:%S:%f"))
    #sys.stdout = open(LOG_FILE, 'wb', buffering=0)
    # change HOST to restrict the origin of incoming connections
    HOST = ''
    SocketServer.TCPServer.allow_reuse_address = True

    # Create the server, binding to HOST on dedicated port
    reportserver = SocketServer.TCPServer((HOST, REPORT_SERVER_PORT), MyTCPReportHandler)
    optoutserver = SocketServer.TCPServer((HOST, OPTOUT_SERVER_PORT), MyTCPOptOutHandler)
        
    reportfilter = ReportFilter()
    reportfilter.load_white_list(WHITE_LIST_FILE)
    reportfilter.load_black_list(BLACK_LIST_FILE)
    
    reportserver_thread = threading.Thread(target=reportserver.serve_forever)
    reportserver_thread.setDaemon(True)
    reportserver_thread.start()
    
    optoutserver_thread = threading.Thread(target=optoutserver.serve_forever)
    optoutserver_thread.setDaemon(True)
    optoutserver_thread.start()

    if BLIND_MODE == True:
        logger.info("Blind mode activated")
        cap = open_iface(MONITOR_IFACE)
        if USING_SENSOR:
            sensorserver = SocketServer.TCPServer((HOST, FRONTEND_PORT), TCPSensorHandler)
            sensorserver_thread = threading.Thread(target=sensorserver.serve_forever)
            sensorserver_thread.setDaemon(True)
            sensorserver_thread.start()
    #else:
    # Also open port in non-blind mode case
    queryserver = SocketServer.TCPServer((HOST, QUERY_SERVER_PORT), MyTCPQueryHandler)
    queryserver_thread = threading.Thread(target=queryserver.serve_forever)
    queryserver_thread.setDaemon(True)
    queryserver_thread.start()

    if USE_DATE_SYNC == True:
        date_frontend_server = SocketServer.TCPServer((HOST, DATE_FRONTEND_PORT), date_frontend_handler)
        date_frontend_server_thread = threading.Thread(target=date_frontend_server.serve_forever)
        date_frontend_server_thread.setDaemon(True)
        date_frontend_server_thread.start()
        date_node_server = SocketServer.TCPServer((HOST, NODE_PORT), date_node_handler)
        date_node_server_thread = threading.Thread(target=date_node_server.serve_forever)
        date_node_server_thread.setDaemon(True)
        date_node_server_thread.start()

    delete_expired_devices()
    delete_expired_blacklist()
    time_first_frame = datetime.now()
    while 1:
        if BLIND_MODE == True:
            try:
                (header, packet) = cap.next()
                now = datetime.now()
                time_diff = to_milliseconds(now - time_first_frame)
                detect_close_device(packet, header)
                time_first_frame = now
            except pcapy.PcapError:
                logger.warning('Interface went down, waiting and trying to bring it up again...')
                time.sleep(1)
                cap = open_iface(MONITOR_IFACE)
        else:
            time.sleep(1)
