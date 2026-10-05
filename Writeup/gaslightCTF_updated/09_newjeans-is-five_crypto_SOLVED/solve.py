from pwn import xor

def ToMatrix(h):
    m = [[0]*4 for _ in range(4)]
    for i in range(16): m[i%4][i//4] = h[2*i:2*i+2]
    return m

def FromMatrix(m): return ''.join(m[i][j] for j in range(4) for i in range(4))

def ShiftRows(s):
    s[1] = [s[1][1], s[1][2], s[1][3], s[1][0]]
    s[2] = [s[2][2], s[2][3], s[2][0], s[2][1]]
    s[3] = [s[3][3], s[3][0], s[3][1], s[3][2]]
    return s

def InvShiftRows(s):
    s[1] = [s[1][3], s[1][0], s[1][1], s[1][2]]
    s[2] = [s[2][2], s[2][3], s[2][0], s[2][1]]
    s[3] = [s[3][1], s[3][2], s[3][3], s[3][0]]
    return s

def GMul(a, b):
    b = int(b, 16); p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a <<= 1
        if a & 0x100: a ^= 0x11b
        b >>= 1
    return p

def MixColumns(s):
    t = [[0]*4 for _ in range(4)]
    for j in range(4):
        t[0][j] = hex(GMul(2,s[0][j])^GMul(3,s[1][j])^int(s[2][j],16)^int(s[3][j],16))[2:].zfill(2)
        t[1][j] = hex(int(s[0][j],16)^GMul(2,s[1][j])^GMul(3,s[2][j])^int(s[3][j],16))[2:].zfill(2)
        t[2][j] = hex(int(s[0][j],16)^int(s[1][j],16)^GMul(2,s[2][j])^GMul(3,s[3][j]))[2:].zfill(2)
        t[3][j] = hex(GMul(3,s[0][j])^int(s[1][j],16)^int(s[2][j],16)^GMul(2,s[3][j]))[2:].zfill(2)
    return t

def InvMixColumns(s):
    t = [[0]*4 for _ in range(4)]
    for j in range(4):
        t[0][j] = hex(GMul(0xe,s[0][j])^GMul(0xb,s[1][j])^GMul(0xd,s[2][j])^GMul(0x9,s[3][j]))[2:].zfill(2)
        t[1][j] = hex(GMul(0x9,s[0][j])^GMul(0xe,s[1][j])^GMul(0xb,s[2][j])^GMul(0xd,s[3][j]))[2:].zfill(2)
        t[2][j] = hex(GMul(0xd,s[0][j])^GMul(0x9,s[1][j])^GMul(0xe,s[2][j])^GMul(0xb,s[3][j]))[2:].zfill(2)
        t[3][j] = hex(GMul(0xb,s[0][j])^GMul(0xd,s[1][j])^GMul(0x9,s[2][j])^GMul(0xe,s[3][j]))[2:].zfill(2)
    return t

# L^{-1}: обратная цепочка без ключей (инверсия SR,MC x9,SR)
def LinDec(y):
    s = ToMatrix(y)
    s = InvShiftRows(s)
    for _ in range(9):
        s = InvMixColumns(s)
        s = InvShiftRows(s)
    return FromMatrix(s)

pt1 = "696e636f6d70726568656e7369626c65"
ct1 = "94ae785acdb0d7c919f4893697659c8c"
ct2 = "58f86ce660590bb05495c0dcd2d4d438"

x  = LinDec(xor(bytes.fromhex(ct1), bytes.fromhex(ct2)).hex())
flag = xor(bytes.fromhex(pt1), bytes.fromhex(x))
print(flag.decode())