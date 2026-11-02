#!/usr/bin/env python3

import hashlib
import struct


TARGET = bytes.fromhex(
    "0502f285cdf9105600a27444181c301609e2a30aaa7516c555f60802b066ad40"
)

MASK = bytes.fromhex(
    "62e8732e8602c5dd3c16a976ae2a8991d4a18ed112e7405fbfb1352674256bfffdfe12332534e3b3fc9581c945e0a6"
)


def mgf1(seed: bytes, length: int) -> bytes:
    result = b""

    for counter in range((length + 31) // 32):
        result += hashlib.sha256(
            seed + struct.pack(">I", counter)
        ).digest()

    return result[:length]


def crypto_check(key: bytes) -> bool:
    if len(key) != 24:
        return False

    seed = hashlib.sha256(key).digest()

    generated = mgf1(seed, 47)

    config = bytes(
        a ^ b
        for a, b in zip(generated, MASK)
    )

    return hashlib.sha256(config).digest() == TARGET


if __name__ == "__main__":
    print("crypto check:")
    print(crypto_check(b"A" * 24))