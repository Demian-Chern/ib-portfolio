#!/usr/bin/env python3
"""
DEADFACE CTF — "checkmate" calling card.

The cipher is Vigenère. Each key letter is the letter that the image board
shows on the destination square of one of Carlsen's (White's) moves.
Only letters are encrypted; letter case is kept, and digits and "_" are left
as they are and do not use up a key letter.
"""
import re

# Board from the image: top row = rank 8, left column = file a
BOARD = [
    "AIWYAEIO",  # 8
    "JBKBFJPU",  # 7
    "XLCMKQVA",  # 6
    "ZCNDOWBE",  # 5
    "DGLPEQFI",  # 4
    "HMRXRFSK",  # 3
    "NSYCGTGU",  # 2
    "TZDHJLVH",  # 1
]

# Carlsen – Indjic, 2026: White's moves only
WHITE_MOVES = [
    "c4", "g3", "Bg2", "Nf3", "Nh4", "Nf5", "Nc3", "d3", "g4", "Bxe4",
    "Nxh6", "Rg1", "d4", "Qd3", "Nd5", "Bd2", "a3", "O-O-O", "cxd5",
    "Bxg5", "Rxg5", "Rdg1", "Bf3", "Kb1", "e3", "Qf5", "Ka2", "e4",
    "Qh7", "Qxh8+", "Rxg5",
]

CIPHERTEXT = "nZ3ipU8_yy3p5_hvyKi0"


def square_letter(square: str) -> str:
    """'e4' -> letter on that square of the board."""
    file = ord(square[0]) - ord("a")
    rank = int(square[1])
    return BOARD[8 - rank][file]


def destination(san: str) -> str:
    """Destination square of a white move written in SAN."""
    if san.startswith("O-O-O"):
        return "c1"
    if san.startswith("O-O"):
        return "g1"
    return re.findall(r"[a-h][1-8]", san)[-1]


def build_key(moves):
    return "".join(square_letter(destination(m)) for m in moves)


def vigenere_decrypt(text: str, key: str) -> str:
    out, i = [], 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[i % len(key)]) - ord("A")
            i += 1
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


if __name__ == "__main__":
    key = build_key(WHITE_MOVES)
    for n, m in enumerate(WHITE_MOVES[:13], 1):
        print(f"{n:>2}. {m:<6} -> {destination(m)} = {square_letter(destination(m))}")
    print("\nKey:      ", key)
    plaintext = vigenere_decrypt(CIPHERTEXT, key)
    print("Plaintext:", plaintext)
    print("Flag:     ", f"deadface{{{plaintext}}}")