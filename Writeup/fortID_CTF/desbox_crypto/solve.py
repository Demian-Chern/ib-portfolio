
from pwn import *

HOST = "desbox-0defab48eba7.inst4.ctf.fortid.com"   
PORT = 1337     
ssl = True

p0 = 0x00
q0 = 0x10
pp0 = p0 ^ 0xFF
qq0 = q0 ^ 0xFF

key_a = bytearray([p0] * 24)
key_a[0] = q0

key_b = bytearray([pp0] * 24)
key_b[1] = qq0

key_a_hex = bytes(key_a).hex()
key_b_hex = bytes(key_b).hex()

io = remote(HOST, PORT,ssl = True)
io.recvuntil(b"C:\\>")

MAX_TRIES = 60
for attempt in range(1, MAX_TRIES + 1):
    io.sendline(b"KEYB")
    io.recvuntil(b"KEY A> ")
    io.sendline(key_a_hex.encode())
    io.recvuntil(b"KEY B> ")
    io.sendline(key_b_hex.encode())

    io.recvuntil(b"encrypted under Key A:\n")
    ct_hex = io.recvline().strip().decode()
    ct = bytes.fromhex(ct_hex)
    ct_comp = bytes(x ^ 0xFF for x in ct)

    io.recvuntil(b"Debug ciphertext> ")
    io.sendline(ct_comp.hex().encode())

    io.recvuntil(b"Debug output:\n")
    out_hex = io.recvline().strip().decode()
    out = bytes.fromhex(out_hex)
    candidate = bytes(x ^ 0xFF for x in out)

    log.info(f"attempt {attempt}: {candidate}")
    if b"flag" in candidate.lower() or candidate.isascii() and candidate.strip(b"\x00").isascii():
        print("CANDIDATE:", candidate)

    io.recvuntil(b"C:\\>")

io.close()