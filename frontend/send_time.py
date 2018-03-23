#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import socket
import time
import sys

if len(sys.argv) > 2:
    HOST, PORT = sys.argv[1], sys.argv[2]
else:
    HOST, PORT = "localhost", 4004

DATE_FORMAT = "%F %H:%M:%S %z"
curtime = time.strftime(DATE_FORMAT, time.gmtime())
sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock2.connect((HOST, 4004))
print "sending:", curtime
sock2.sendall(curtime)
print sock2.recv(100)
