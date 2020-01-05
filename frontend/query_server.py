#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# usage :
# python query_server.py [all|stats|<address>] [lo|v]

import socket
import sys
import json
import time
import os

DATE_FORMAT = "%F %H:%M:%S %z"
save = False
LOG_PATH = 'log.txt'
OUIs = {}

def print_zone(name, j, f):
    if name in j["devices_by_zone"]:
        f.write(str(j["devices_by_zone"][name]) + ",")
    else:
        f.write("0,")

def is_random_mac(raw_mac):
    mac = raw_mac[0:2].decode("hex") + raw_mac[3:5].decode("hex") + raw_mac[6:8].decode("hex")
    mac_nb = [ord(c) for c in mac]
    # random mac have locally administered bit set to 1
    return (mac_nb[0] & 0x02 == 2)

def resolve_oui(device_id):
    oui = device_id[:8]
    if oui in OUIs:
        return OUIs[oui]
    else:
        return "unknown"

#load OUIs
with open("../server/oui.txt", 'r') as oui_file:
    for l in oui_file:
        infos = l.split("(hex)")
        mac = infos[0].strip().replace("-", ":").lower()
        vendor = infos[1].strip()
        OUIs[mac] = vendor

if len(sys.argv) < 2:
    print "Usage: python2 query_server.py [all|stats|<address>] [lo|v]"
    sys.exit(1)

if len(sys.argv) > 2:
    if sys.argv[2] in ['lo', 'l', 'localhost', '127.0.0.1']:
        HOST, PORT = "localhost", 4002
    elif sys.argv[2] in ['vitrine', 'v', '10.0.10.1']:
        HOST, PORT = "10.0.10.1", 4002
    else:
        print "Unrecognized receiver"
        sys.exit(1)
    if len(sys.argv) > 3:
        save = True
else:
    HOST, PORT = "172.23.0.1", 4002
data = sys.argv[1].lower()
dump_file_name = "device_" + data.replace(':','-') + ".json"

# Create a socket (SOCK_STREAM means a TCP socket)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to server and send data
    print "Sending:", data
    sock.connect((HOST, PORT))
    sock.sendall(bytes(data + "\n"))

    # Receive data from the server and shut down
    new_data = sock.recv(1024)
    received = ""
    while new_data:
        received += new_data
        new_data = sock.recv(1024)
finally:
    sock.close()

print("Sent:     {}".format(data))
print("Received: {}".format(received))
encoded = json.dumps(received)
print(json.dumps(received))

if received == "unknown":
    print "Unknown device"
elif received == "blacklisted":
    print "Blacklisted device"
else:
    j = json.loads(received)
    if j["message"] == "Time not synchronized":
        curtime = time.strftime(DATE_FORMAT, time.gmtime())
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect((HOST, int(j["port"])))
        sock2.sendall(curtime)
        print "Time not synchronized, time sent to server."
    else:
        if data == 'all':
            print
            print "Seen devices:"
            random_macs = 0
            for x in j["devices"]:
                if not is_random_mac(x):
                    print "%s (%s)" % (x, resolve_oui(x))
                else:
                    random_macs += 1
            if random_macs > 0:
                print "And %d random MAC addresses" % random_macs
        elif data == 'stats':
            print
            print "Number of devices:", sum([j["devices_by_zone"][x] for x in j["devices_by_zone"]])
            print
            print "Devices by zone:"
            for z in j["devices_by_zone"]:
                print "-", z, ":", j["devices_by_zone"][z]
            if "nb_blacklisted_devices" in j:
                print "Number of blacklisted devices:", j["nb_blacklisted_devices"]
            if save:
                file_exists = os.path.isfile(LOG_PATH)
                with open(LOG_PATH, 'a+') as f:
                    with open(sys.argv[3], 'r') as f_topology:
                        topology = json.load(f_topology)
                    if not file_exists:
                        # print first header
                        f.write('time,')
                        for z in topology["zones"]:
                            f.write(z["name"] + ",")
                        f.write("nb_blacklisted_devices\n")
                    f.write(str(int(time.time())) + ",")
                    for z in topology["zones"]:
                        print_zone(z["name"], j, f)
                    if "nb_blacklisted_devices" in j:
                        f.write(str(j["nb_blacklisted_devices"]) + "\n")
                    else:
                        f.write("0\n")

        elif data == 'nodes':
            print "Nodes:"
            for z in j["nodes"]:
                print z, j["nodes"][z]
        else:
            import draw_timeline
            draw_timeline.draw_figure(j)
            #with open(dump_file_name, 'w') as outfile:
            #    json.dump(j, outfile)
