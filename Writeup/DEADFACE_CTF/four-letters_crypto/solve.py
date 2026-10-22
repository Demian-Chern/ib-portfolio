bits = "001100000 10110011 001110101 100111010 010101000 101111101 100101100 00001100 10001010 100000010 0100001110".split()
gates = "XXONO NXNOA OAOON NXXAO NAAXO XANXO ANOXA ANOXN NONOX ANXAX AOAAX".split()

ops = {"A": lambda a, b: a & b, "O": lambda a, b: a | b, "X": lambda a, b: a ^ b}

flag = ""
for b, g in zip(bits, gates):
    v = list(map(int, b))
    i, out = 0, []
    for op in g:
        if op == "N":
            out.append(1 - v[i]); i += 1
        else:
            out.append(ops[op](v[i], v[i + 1])); i += 2
    assert i == len(v), (b, g)
    flag += chr(64 + int("".join(map(str, out)), 2))

print(f"deadface{{{flag}}}")