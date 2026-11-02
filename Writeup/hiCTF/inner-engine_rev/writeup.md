# Writeup — `inner-engine` (reverse / crackme)

> **TL;DR**
> - Ключ активации: **`L1c#N0d3_7mQ9f3a2b8c6d1e`** (ровно 24 байта)
> - Содержимое «активационной записи» (флаг): **`hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}`**
>
> ```
> $ inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1e'
> hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}
> ```

Задание: *«Node-locked activation. Run the checker with your activation key as the only argument: `inner-engine <key>`. A valid key unseals the activation record; anything else stays sealed.»*

Правильный ключ «распечатывает» (unseal) активационную запись; любой другой выводит `license sealed`.

---

## 1. Первичная разведка

```
$ file inner-engine
inner-engine: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=b8599e1f..., for GNU/Linux 3.2.0, stripped
```

- 40000 байт, stripped, x86-64 Linux.
- `strings` **не даёт ни одной читаемой строки** — ни `license`, ни `.rs`-путей паник, ни форматных строк. Для Rust-бинаря это ненормально: обычно паники «протекают» путями исходников. Вывод: строки **обфусцированы** и собираются/расшифровываются в рантайме.
- Импорты красноречивы: `mmap`/`munmap`, `fopen`/`fread`/`fwrite`/`fseeko`/`ftello`/`fstat`, `pthread_mutex_*`, `getrandom`. Файловый ввод + отображение памяти → ключ не сравнивается как строка, а **расшифровывает** какой-то блок.

Структура типична для Rust: тонкий `main` (`0x400530`) складывает `argc/argv/envp` в глобалы и зовёт `lang_start`-обёртку (`0x403814`), которая в итоге вызывает пользовательский `main` (`0x4047ad`).

---

## 2. Антиотладка

Функция `0x403dd0`:

1. `fs::read_to_string("/proc/self/status")` (строка хранится как «boxed»-строка, см. ниже);
2. ищет строку, начинающуюся с `"TracerPid:"`;
3. проверяет, что значение равно `"0"`.

Если `TracerPid != 0` (т.е. процесс трассируется `strace`/`gdb`/`ptrace`), программа уходит на ветку отказа. Поэтому «в лоб» под трассировщиком бинарь ничего полезного не делает.

> Для анализа я снял проверку **только в отдельной копии** (`0x403dd0 → xor eax,eax; ret`), чтобы можно было подключить отладчик. Итоговый ключ проверялся на **оригинальном, немодифицированном** бинаре.

### «Boxed»-строки

Строки лежат как структура: 8-байтный заголовок (младшие 7 байт — длина, байт 7 — тег `0x40`), сразу за ним — сами UTF-8 данные. Именно поэтому компаратор читает данные по смещению `+8`:

```
0x4064c0: 11 00 00 00 00 00 00 40  2f 70 72 6f 63 2f 73 65  |.......@/proc/se|
0x4064d0: 6c 66 2f 73 74 61 74 75  73 ...                    |lf/status       |
          └── len=0x11, tag=0x40 ┘  └──── "/proc/self/status" (17) ────┘
```

---

## 3. Криптография проверки

Три ключевых примитива найдены статически.

### 3.1 SHA-256 (`0x404004`)

Опознаётся мгновенно по init-константам и таблице раундовых констант:

```
H0..H7: 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
K[0..]: 428a2f98 71374491 b5c0fbcf e9b5dba5 ...   (таблица @ 0x406320)
```

Плюс характерные сдвиги `σ0 (ror7/rol14/shr3)`, `σ1 (ror17/rol13/shr10)`, `Σ0/Σ1`.

### 3.2 Генератор гаммы — MGF1 (`0x404336`)

```
keystream = b""
counter = 0
while len(keystream) < 40:
    keystream += SHA256( digest || big_endian_uint32(counter) )
    counter += 1
keystream = keystream[:40]
```

То есть MGF1-SHA256 от 32-байтного seed, обрезанный до 40 байт.

### 3.3 Верификатор (`0x404416`)

```
digest    = SHA256(key)                 # key = 24 байта argv[1]
keystream = MGF1(digest, 40)
record    = CIPHERTEXT ^ keystream       # 40 байт XOR 40 байт
if SHA256(record) == TARGET_HASH:
    print(record)                        # «unseal»
    success_flag = 1
else:
    print("license sealed")
```

Константы из `.rodata`:

```
CIPHERTEXT @ 0x4062e0 (40): 9a40bd7dd28fe31997a3de379af40bd87d815f4413fdbd86100c465179799c4202f983c0d7974e1c
TARGET_HASH @ 0x4062c0 (32): e4f870dad765bfab3d282870ec136b8f450dc8c606cd894b9ea78c91736a5272
```

Строка `"license sealed\n"` восстанавливается из 15 байт по адресу `0x406298` операцией `XOR 0x3c` (функция `0x404691`).

> Важно: проверяется `SHA256(record)`, а `record` зависит от ключа. Инвертировать SHA нельзя — значит, ключ нужно получить **не** из крипто-части, а из логики проверки (которая оказалась в байткоде VM).

---

## 4. «Inner engine» — байткодная виртуальная машина

Название не случайно. Пользовательский `main` (`0x4047ad`):

1. `0x404588` — инициализирует **таблицу диспетчеризации** опкодов;
2. собирает `argv[1..]`;
3. **требует ровно 1 аргумент длиной `0x18 = 24` байта** (вот почему `AAAA-BBBB-CCCC-DDDD` (19 символов) отсекался сразу);
4. копирует ключ в `0x40aa70`;
5. запускает интерпретатор VM (`0x404709`).

Флаг успеха — байт `0x40aa40`: если VM его выставил в 1 (верификатор отработал), запись уже напечатана; иначе печатается `license sealed`.

### Интерпретатор (`0x404709`)

- **байткод**: `0x405e00`, длина `0x492 = 1170` байт;
- **формат инструкции**: 5 байт = `1 байт опкод` + `4 байта little-endian immediate`;
- **PC** в `0x40aa58` (байтовое смещение, шаг +5), лимит `0x492`;
- **диспетч**: `handler = *(void**)(0x40a240 + opcode*8)`;
- регистровый файл: `0x40aa60`; стек операндов (Vec<u32>): `0x40aa80`; «топливо» (лимит инструкций) `0xf4241`.

### Карта опкодов

| opcode | handler | семантика |
|-------:|---------|-----------|
| `0x17` | `0x403c14` | `PUSHI imm` |
| `0x4c` | `0x403c1c` | `PUSH key[imm]` |
| `0x95` | `0x403c30` | `PUSH reg[imm]` (LOAD) |
| `0x38` | `0x403c9c` | `reg[imm] = POP` (STORE) |
| `0xa3` | `0x403c64` | `DUP` |
| `0x6e` | `0x403c78` | `SWAP` |
| `0x2b` | `0x403c9a` | `DROP` |
| `0x7d` | `0x403cb1` | `ADD` |
| `0xc1` | `0x403cc7` | `SUB` (b − a) |
| `0x52` | `0x403cde` | `XOR` |
| `0x8a` | `0x403cf5` | `MUL` |
| `0x33` | `0x403d0d` | `AND` |
| `0xbf` | `0x403d24` | `OR` |
| `0x64` | `0x403d3b` | `ROL imm` |
| `0xcc` | `0x403d8c` | `SHL imm` |
| `0x71` | `0x403d6c` | `NEG` |
| `0xae` | `0x403d7c` | `NOT` |
| `0x1e` | `0x403d51` | `EQ` (push a==b) |
| `0xd7` | `0x403be2` | `JMP imm` |
| `0x49` | `0x403db7` | `JZ imm` (прыжок, если top==0) |
| `0xe5` | `0x403bf0` | `HALT1` |
| `0x5a` | `0x403bfc` | `HALT2` |
| `0xf2` | `0x403fe3` | `ANTIDBG` (push !traced) |
| `0x0b` | `0x404416` | `VERIFY` (крипто-проверка, см. §3.3) |

Таблицу я снял под отладчиком (на копии со снятой антиотладкой), а сам байткод — прямо из файла (он статичен в `.rodata`).

---

## 5. Дизассемблирование байткода

Паттерн программы: загрузить `reg[0..3] = key[0..3]` (с «мусорными» DUP/DROP/SWAP/OR-0 для запутывания), затем серия проверок вида «вычислить выражение от байтов ключа → `EQ` с константой → `JZ HALT`». Каждая невыполненная проверка уводит на `HALT`. Последняя инструкция — `VERIFY`.

Фрагмент листинга:

```
  0 [  0] ANTIDBG            ; push !traced
  5 [  1] JZ      -> HALT    ; если трассируется — выход
 10 [  2] PUSHKEY key[0]
 ...        reg[0..3] = key[0..3]
115 [ 23] PUSHKEY key[5]
120 [ 24] PUSHKEY key[6]
125 [ 25] XOR
130 [ 26] PUSHI   0x54
135 [ 27] EQ                 ; key[5]^key[6] == 0x54 ?
140 [ 28] JZ      -> HALT
 ...
1165 [233] VERIFY
```

---

## 6. Система уравнений на байты ключа

Все 23 проверки (сложение — по модулю 256):

```
 1.  key[5] ^ key[6]                                   == 0x54
 2.  (key[9]  + key[10]) & 0xff                        == 0xa4
 3.  (key[10] + key[11]) & 0xff                        == 0xbe
 4.  (key[12] + key[13]) & 0xff                        == 0x9f
 5.  (key[13] + key[14]) & 0xff                        == 0x99
 6.  (key[14] + key[15]) & 0xff                        == 0x94
 7.  (key[16] + key[17]) & 0xff                        == 0x94
 8.  (key[17] + key[18]) & 0xff                        == 0x9a
 9.  (key[18] + key[19]) & 0xff                        == 0x9b
10.  (key[19] + key[20]) & 0xff                        == 0x99
11.  (key[20] + key[21]) & 0xff                        == 0x9a
12.  (key[22] + key[23]) & 0xff                        == 0x96
13.  (key[23] + key[0])  & 0xff                        == 0xb1
14.  (key[3]  * key[15]) & 0xff                        == 0x43
15.  (key[7]  * key[21]) & 0xff                        == 0xec
16.  (key[11] * key[19]) & 0xff                        == 0x53
17.  key[0] ^ key[8]  ^ key[16]                        == 0x21
18.  key[4] ^ key[12] ^ key[20]                        == 0x41
19.  key[2] ^ key[10] ^ key[18]                        == 0x36
20.  (key[0]+key[4]+key[8]+key[12]+key[16]+key[20])&ff == 0x9a
21.  key[1]^key[5]^key[9]^key[13]^key[17]^key[21]      == 0x56
22.  (key[2]+key[7]+key[10]+key[15]+key[18]+key[23])&ff== 0x01
23.  key[3]^key[6]^key[11]^key[14]^key[19]^key[22]     == 0x77
```

Структура решаема без перебора всего пространства:

- **цепочки сумм** задают большинство байт через 4 параметра `key[9]`, `key[12]`, `key[16]`, `key[22]`:
  - `key[10],key[11]` ← `key[9]`
  - `key[13],key[14],key[15]` ← `key[12]`
  - `key[17..21]` ← `key[16]`
  - `key[23],key[0]` ← `key[22]`
- `key[3]`, `key[7]` — из mul-уравнений (обратный по модулю 256; множитель обязан быть нечётным, т.к. `0x43` нечётно);
- `key[8]=0x21^key[0]^key[16]`, `key[4]=0x41^key[12]^key[20]`, `key[2]=0x36^key[10]^key[18]`;
- `key[6]=0x77^key[3]^key[11]^key[14]^key[19]^key[22]`, `key[5]=key[6]^0x54`, `key[1]` — из уравнения 21;
- уравнения 16, 20, 22 становятся проверками.

Итого весь ключ определяется 4 параметрами; с ограничением «печатный ASCII» остаётся всего **два** кандидата, а истину выбирает `VERIFY`.

---

## 7. Солвер

```python
import hashlib, struct

d = open('inner-engine','rb').read(); base = 0x400000
CT = d[0x4062e0-base:0x4062e0-base+40]
H  = d[0x4062c0-base:0x4062c0-base+32]

def verify(key):                      # key: 24 байта
    dg = hashlib.sha256(bytes(key)).digest()
    ks = b""; c = 0
    while len(ks) < 40:
        ks += hashlib.sha256(dg + struct.pack('>I', c)).digest(); c += 1
    rec = bytes(CT[i] ^ ks[i] for i in range(40))
    return hashlib.sha256(rec).digest() == H, rec

def inv(t, f):                        # все x: (x*f) % 256 == t
    return [x for x in range(256) if (x*f) & 0xff == t]

P = lambda b: 0x20 <= b <= 0x7e
R = range(0x20, 0x7f)
cands = []
for p9 in R:
    k9=p9; k10=(0xa4-p9)&0xff; k11=(p9+0x1a)&0xff
    if not(P(k10) and P(k11)): continue
    for p12 in R:
        k12=p12; k13=(0x9f-p12)&0xff; k14=(p12-6)&0xff; k15=(0x9a-p12)&0xff
        if not all(P(x) for x in (k13,k14,k15)): continue
        k3s=[x for x in inv(0x43,k15) if P(x)]
        if not k3s: continue
        for p16 in R:
            k16=p16; k17=(0x94-p16)&0xff; k18=(p16+6)&0xff
            k19=(0x95-p16)&0xff; k20=(p16+4)&0xff; k21=(0x96-p16)&0xff
            if not all(P(x) for x in (k17,k18,k19,k20,k21)): continue
            if (k11*k19)&0xff != 0x53: continue           # eq16
            k7s=[x for x in inv(0xec,k21) if P(x)]
            if not k7s: continue
            for p22 in R:
                k22=p22; k23=(0x96-p22)&0xff; k0=(p22+0x1b)&0xff
                if not(P(k23) and P(k0)): continue
                k8=(0x21^k0^k16)&0xff
                k4=(0x41^k12^k20)&0xff
                k2=(0x36^k10^k18)&0xff
                if not all(P(x) for x in (k8,k4,k2)): continue
                if (k0+k4+k8+k12+k16+k20)&0xff != 0x9a: continue   # eq20
                for k3 in k3s:
                    k6=(0x77^k3^k11^k14^k19^k22)&0xff
                    k5=(k6^0x54)&0xff
                    if not(P(k6) and P(k5)): continue
                    for k7 in k7s:
                        if (k2+k7+k10+k15+k18+k23)&0xff != 0x01: continue  # eq22
                        k1=(0x56^k5^k9^k13^k17^k21)&0xff
                        if not P(k1): continue
                        cands.append(bytes([k0,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,
                                            k12,k13,k14,k15,k16,k17,k18,k19,k20,k21,k22,k23]))

for c in set(cands):
    ok, rec = verify(c)
    if ok:
        print("KEY   :", c.decode())
        print("RECORD:", rec.decode())
        break
```

Вывод:

```
ASCII algebraic candidates: 2
KEY   : L1c#N0d3_7mQ9f3a2b8c6d1e
RECORD: hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}
```

---

## 8. Проверка на оригинале

```
$ ./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1e'
hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}

$ ./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1f'   # сосед по байту
license sealed
```

---

## 9. Итоги

| Что | Значение |
|-----|----------|
| **Ключ** | `L1c#N0d3_7mQ9f3a2b8c6d1e` |
| **Флаг** | `hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}` |

Чему учит задача:

1. **Stripped Rust** + ручная обфускация строк → опора на динамику и структуру рантайма, а не на `strings`.
2. **Антиотладка через `/proc/self/status` (TracerPid)** — обходится патчем проверки в анализируемой копии (финал — всегда на оригинале).
3. **Байткодная VM** — весь контроль ключа вынесен в интерпретируемый байткод; нужно восстановить набор опкодов, диспетчер и формат инструкции.
4. **Разделение проверки**: быстрый алгебраический «чек-сумм» фильтр в VM + криптографический `VERIFY` (SHA-256 + MGF1 + XOR). Алгебра сводит ключ к нескольким параметрам, крипто выбирает единственный верный.
5. «Node-locked» оказалось декорацией: ничего машинно-специфичного не читается (единственный `getrandom` — это сид HashMap в std Rust), поэтому ключ полностью определён самим бинарём.
