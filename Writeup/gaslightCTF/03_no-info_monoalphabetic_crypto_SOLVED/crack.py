import string

with open('output6.txt') as f:
    ct = f.readline().strip()

alphabet = string.ascii_lowercase
N = len(ct)
print("Ciphertext length:", N)

# English letter frequencies (percent)
freq = {
 'a':8.167,'b':1.492,'c':2.782,'d':4.253,'e':12.702,'f':2.228,'g':2.015,
 'h':6.094,'i':6.966,'j':0.153,'k':0.772,'l':4.025,'m':2.406,'n':6.749,
 'o':7.507,'p':1.929,'q':0.095,'r':5.987,'s':6.327,'t':9.056,'u':2.758,
 'v':0.978,'w':2.360,'x':0.150,'y':1.974,'z':0.074
}

def chi_squared(text):
    n = len(text)
    counts = {c:0 for c in alphabet}
    for c in text:
        counts[c]+=1
    chi = 0
    for c in alphabet:
        observed = counts[c]
        expected = freq[c]/100*n
        if expected>0:
            chi += (observed-expected)**2/expected
    return chi

def unshift_progressive(ct, m):
    # ct'[i] = (ct[i] - i//m) mod 26
    out = []
    for i,ch in enumerate(ct):
        v = (alphabet.index(ch) - (i//m)) % 26
        out.append(alphabet[v])
    return ''.join(out)

def crack_vigenere(ct2, m):
    key = ''
    for col in range(m):
        col_text = ct2[col::m]
        best_chi = None
        best_shift = 0
        for shift in range(26):
            # try shift: decrypted = ct - key_char
            decrypted = ''.join(alphabet[(alphabet.index(c)-shift)%26] for c in col_text)
            chi = chi_squared(decrypted)
            if best_chi is None or chi < best_chi:
                best_chi = chi
                best_shift = shift
        key += alphabet[best_shift]
    return key

results = []
for m in range(1, 21):
    ct2 = unshift_progressive(ct, m)
    key = crack_vigenere(ct2, m)
    # decrypt fully
    pt = ''.join(alphabet[(alphabet.index(ct2[i]) - alphabet.index(key[i%m]))%26] for i in range(len(ct2)))
    score = chi_squared(pt)
    results.append((score, m, key, pt))

results.sort()
for score, m, key, pt in results[:8]:
    print(f"m={m} key={key} score={score:.1f}")
    print(pt[:120])
    print('---')
