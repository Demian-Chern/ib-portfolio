#!/usr/bin/env python3
from pwn import *

HOST = "sticker-booth-de693854d63c.inst18.ctf.fortid.com"
PORT = 1337

def go(name, cmds):
    print(f"\n===== {name} =====")
    try:
        io = remote(HOST, PORT, ssl=True, timeout=5)
        print(io.recvline().decode().strip())
        for c in cmds:
            io.sendline(c if isinstance(c, bytes) else c.encode())
        print(io.recvall(timeout=3).decode(errors="replace"))
        io.close()
    except Exception as e:
        print("ERROR:", e)

# 1. Точная граница 1x1 vs 2x1
go("1x1", [
    "photo p 1 1 11223344",
    "builtin b heart",
    "mono p",
    "print",
])

go("2x1", [
    "photo p 2 1 1122334455667788",
    "builtin b heart",
    "mono p",
    "print",
])

# 2. Вставляем маленький padding-объект между photo и builtin
go("photo + upload pad + builtin + mono", [
    "photo p 2 1 1122334455667788",
    "upload pad 41424344",
    "builtin b heart",
    "mono p",
    "print",
])

go("photo + caption pad + builtin + mono", [
    "photo p 2 1 1122334455667788",
    "caption pad AAAA",
    "builtin b heart",
    "mono p",
    "print",
])

# 3. Несколько маленьких photo, mono только по последнему
go("chain of 1x1 + last mono", [
    "photo a 1 1 11223344",
    "photo b 1 1 11223344",
    "photo c 1 1 11223344",
    "builtin b heart",
    "mono c",
    "print",
])

# 4. mono два раза по 1x1
go("1x1 mono twice", [
    "photo p 1 1 11223344",
    "builtin b heart",
    "mono p",
    "mono p",
    "print",
])

# 5. photo 2x1, но mono после того, как builtin уже создан (порядок)
go("builtin then 2x1 mono", [
    "builtin b heart",
    "photo p 2 1 1122334455667788",
    "mono p",
    "print",
])