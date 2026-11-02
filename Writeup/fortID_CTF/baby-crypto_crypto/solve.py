#!/usr/bin/env python3
from pwn import *
import string
import json
import re

HOST = "baby-crypto-a782f13ad96d.inst16.ctf.fortid.com"   # подставь реальный хост
PORT = 1337                       # подставь реальный порт
LOCAL = False
USE_SSL = True

CHARSET = string.ascii_letters + string.digits + "_-"
PROMPT = b"> "

def send_menu(io, choice):
    io.sendline(choice.encode())

def send_secret(io, secret):
    send_menu(io, "1")
    io.recvuntil(b"Enter secret: ")
    io.sendline(secret.encode())
    io.recvuntil(PROMPT)

def do_export(io):
    send_menu(io, "2")
    chunk = io.recvuntil(PROMPT)
    text = chunk.decode(errors="replace")
    m = re.search(r"\{.*\}", text)
    if not m:
        log.error(f"Не нашли JSON в ответе: {text!r}")
        raise RuntimeError("no json")
    return json.loads(m.group(0))

def main():
    if LOCAL:
        io = process(["python3", "-u", "chall.py"])
    elif USE_SSL:
        io = remote(HOST, PORT, ssl=True)
    else:
        io = remote(HOST, PORT)

    io.recvuntil(PROMPT)

    data = do_export(io)
    flag_ct = bytes.fromhex(data["Secret #0"])
    flag_nonce_ct = flag_ct[:8]
    log.info(f"flag ciphertext: {flag_ct.hex()}")

    prefix = "FortID{"
    guesses = []
    for c in CHARSET:
        guess = prefix + c
        send_secret(io, guess)
        guesses.append(guess)

    data = do_export(io)

    found_char = None
    for i, guess in enumerate(guesses, start=1):
        key = f"Secret #{i}"
        if key not in data:
            continue
        ct = bytes.fromhex(data[key])
        if ct[:8] == flag_nonce_ct:
            found_char = guess[-1]
            break

    if found_char is None:
        log.error("Не нашли совпадение nonce — расширь CHARSET")
        return

    log.success(f"8-й байт флага: {found_char!r}")
    known_prefix = prefix + found_char

    pad_len = 200
    our_plain = known_prefix + "A" * pad_len
    send_secret(io, our_plain)

    data = do_export(io)
    our_ct = bytes.fromhex(data[f"Secret #{len(guesses) + 1}"])

    our_plain_bytes = our_plain.encode()
    keystream = bytes(a ^ b for a, b in zip(our_ct, our_plain_bytes))

    recovered = bytes(a ^ b for a, b in zip(flag_ct, keystream))
    log.success(f"Восстановленный флаг (сырые байты): {recovered}")

    try:
        end = recovered.index(b"}") + 1
        print("FLAG:", recovered[:end].decode())
    except ValueError:
        print("FLAG (возможно с мусором в хвосте):", recovered)

    io.close()

if __name__ == "__main__":
    main()