# --- Шаг 1: восстанавливаем keystream из известной пары plaintext/ciphertext ---

known_pt = b"Hello, world"
inter_ct = bytes.fromhex("c68d2a7ec13c03eb380395cf")

assert len(known_pt) == len(inter_ct) == 12

keystream = bytes(p ^ c for p, c in zip(known_pt, inter_ct))
print("keystream (hex):", keystream.hex())

# keystream состоит из 6 регистров по 2 байта: R0=IV, R1..R5 = next_register(...)
registers = [int.from_bytes(keystream[i:i+2], 'big') for i in range(0, len(keystream), 2)]
print("registers:", [hex(r) for r in registers])

# --- Шаг 2: превращаем регистры в непрерывную битовую последовательность ---
# register читается от MSB(bit15, "старый" бит) к LSB(bit0, "новый" бит),
# т.к. в next_register: register = ((register << 1) | feedback) & 0xffff
# т.е. новый бит всегда входит в LSB, а bit15 "вымывается" через 16 шагов.

def reg_to_bits(r):
    return [(r >> (15 - i)) & 1 for i in range(16)]

bits = []
for r in registers:
    bits.extend(reg_to_bits(r))

print("total bits collected:", len(bits))
print(bits)

# --- Шаг 3: Berlekamp-Massey над GF(2), чтобы найти линейную рекуррентность (тапы LFSR) ---

def berlekamp_massey(bits):
    n = len(bits)
    s = bits[:]
    c = [1] + [0]*n
    b = [1] + [0]*n
    L, m, bb = 0, 1, 1
    for N in range(n):
        d = s[N]
        for i in range(1, L+1):
            d ^= c[i] & s[N-i]
        if d == 0:
            m += 1
        elif 2*L <= N:
            t = c[:]
            coef = d * pow(bb, -1, 2) if False else d  # GF(2): division by 1 is identity
            for i in range(len(b)):
                if i+m < len(c):
                    c[i+m] ^= (coef & b[i])
            L = N+1-L
            b = t
            bb = d
            m = 1
        else:
            coef = d
            for i in range(len(b)):
                if i+m < len(c):
                    c[i+m] ^= (coef & b[i])
            m += 1
    return L, c[:L+1]

L, poly = berlekamp_massey(bits)
print("LFSR degree found:", L)
print("connection polynomial (c0..cL), c0 is always 1:", poly)

# --- Шаг 4: проверяем рекуррентность на исходных данных и учимся генерировать дальше ---
# По определению Berlekamp-Massey: s_N = XOR_{i=1..L} (c_i & s_{N-i})

def extend(seed_bits, poly, total_len):
    L = len(poly) - 1
    seq = seed_bits[:]
    while len(seq) < total_len:
        N = len(seq)
        val = 0
        for i in range(1, L+1):
            val ^= poly[i] & seq[N-i]
        seq.append(val)
    return seq

# проверка: возьмём первые L бит как seed и regenerate weiter, сравним с исходными 96 битами
regen = extend(bits[:L], poly, len(bits))
print("Self-consistency check (regenerated == original):", regen == bits)

# --- Шаг 5: атака на output.txt (флаг) ---

out_ct = bytes.fromhex("e989357ec7774be81425bfd007aaf6f30b5342ce52a66776f8b326449b85ed186f1641603546b068dd89ba6b3145")
print("output ct length:", len(out_ct))

guess_prefix = b"gaslightCTF{"
ks_prefix = bytes(p ^ c for p, c in zip(guess_prefix, out_ct[:len(guess_prefix)]))
print("keystream prefix from guess (hex):", ks_prefix.hex())

# первые 2 байта keystream = IV' самого флага
IV2 = int.from_bytes(ks_prefix[:2], 'big')
print("Recovered flag IV:", hex(IV2))

seed_bits = reg_to_bits(IV2)  # 16 бит

# генерируем достаточно бит, чтобы покрыть весь ciphertext (46 байт = 368 бит)
need_bits = len(out_ct) * 8
full_bits = extend(seed_bits, poly, need_bits)

# собираем keystream обратно в байты, регистр за регистром (по 16 бит = 2 байта)
def bits_to_reg(bitlist):
    v = 0
    for b in bitlist:
        v = (v << 1) | b
    return v

full_keystream = bytearray()
for i in range(0, need_bits, 16):
    r = bits_to_reg(full_bits[i:i+16])
    full_keystream.append((r >> 8) & 0xff)
    full_keystream.append(r & 0xff)

full_keystream = bytes(full_keystream[:len(out_ct)])
print("Full keystream (hex):", full_keystream.hex())

flag = bytes(c ^ k for c, k in zip(out_ct, full_keystream))
print("FLAG:", flag)
