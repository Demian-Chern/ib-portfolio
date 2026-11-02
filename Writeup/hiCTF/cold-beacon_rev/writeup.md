# Writeup — `cold-beacon` (reverse)

**Флаг:** `hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}`
**Ключ (`argv[1]`):** `C0ldB34c0n::unl0ck::7a3f`

```
$ ./cold-beacon 'C0ldB34c0n::unl0ck::7a3f'
hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}
$ ./cold-beacon 'что-угодно-другое......'
config sealed
```

---

## 1. Условие

Дан один файл `cold-beacon` (подан под видом «вещдока» IR-2231-A с рабочей станции).
Поведение: `./cold-beacon <key>` — с правильным ключом печатает зашитый конфиг,
иначе выводит `config sealed`. Задача — восстановить конфиг, ключа нет.

## 2. Первичный анализ

```
$ file cold-beacon
ELF 64-bit LSB executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Бинарь **stripped**, но строки выдают рантайм: `cmdline.nim`, `paramStr`,
`IndexDefect`, `syncio.nim`, `readFile`, `SIGSEGV: ... (Attempt to read from nil?)`
→ это программа на **Nim**.

Импорты (`objdump -R`) — только локальный файловый ввод-вывод и работа с памятью:
`fopen, fread, fseeko, ftello, fstat, mmap, munmap, fwrite, setvbuf, pthread_mutex_*`.
**Ни одного сетевого/exec-вызова** (`socket`, `connect`, `system`, `exec`, `fork` отсутствуют).
То есть никакой это не «маяк» — это RE-таск, что подтвердит и формат флага `hiCTF{...}`.

Среди строк сразу видно антиотладку:

```
@/proc/self/status
@TracerPid:
```

## 3. Разбор `.rodata`

Секция `.rodata` (vaddr `0x4057e0`). Файловое смещение здесь = `vaddr − 0x400000`.

| Адрес | Размер | Что это |
|---|---|---|
| `0x405e00` | 14 Б | строка `"config sealed\n"`, обфусцированная XOR `0x5A` |
| `0x405e20` | 32 Б | эталонный `SHA256(plaintext)` — контроль целостности |
| `0x405e40` | 47 Б | **шифртекст** конфига |
| `0x405e80` | 256 Б | таблица констант `K[64]` SHA-256 (`428a2f98…`, little-endian) |
| `0x405f80` | 32 Б | начальные значения `H0..H7` SHA-256 (`6a09e667…`) |
| `0x405fa0` | 23 Б | ожидаемые результаты проверок ключа |
| `0x405fc0` | 23×6 Б | таблица индексов байт ключа для каждой проверки |
| `0x406050` / `0x406070` | 23 Б | таблицы «длина» и «тип операции» для проверок |

Проверка обфускации строки:

```python
blob = bytes.fromhex("3935343c333d7a293f3b363f3e50")
print(bytes(b ^ 0x5A for b in blob).decode())  # -> "config sealed\n"
```

Наличие полных таблиц `K` и `H` однозначно говорит: внутри — вручную
реализованный **SHA-256**.

## 4. Логика проверки ключа

Главная функция (`0x404271`). До любой криптографии ключ проходит «ворота»;
любой проваленный шаг → ветка `config sealed`:

1. **`paramCount() == 1`** — ровно один аргумент (`0x4042bb`).
2. **`len(key) == 0x18`** — ровно **24 символа** (`0x4042dc`).
3. **Валидатор A** (`0x403cff`) — должен вернуть `true`.
4. **Валидатор B** (`0x403dc4`) — должен вернуть `1`.
5. **Антиотладка** (`0x403aec`): читается `/proc/self/status`, парсится
   `TracerPid`. Если отладчик присоединён — принудительно `config sealed`
   (`0x404324`). Вывод: под `gdb`/`strace` таск не решается, нужен статический разбор.

### Валидатор A — 23 алгебраических ограничения

Функция в цикле по `i = 0..22` для каждой проверки берёт из таблиц тип операции
(`0x406070`), длину (`0x406050`), набор индексов байт ключа (`0x405fc0`, по 6 на
проверку) и сверяет результат с `0x405fa0[i]`. Типы операций:

| код | операция |
|---|---|
| 0 | XOR двух байт |
| 1 | сумма двух байт (mod 256) |
| 2 | произведение двух байт (mod 256) |
| 3 | XOR трёх байт |
| 4 | сумма шести байт (mod 256) |
| 5 | XOR шести байт |

Обозначим байты ключа `d[0..23]`. Разобранная система (`&0xff` подразумевается):

```
C0 : d5 ^ d6                               = 0x07
C1 : d9 + d10                              = 0xa8
C2 : d10 + d11                             = 0x74
C3 : d12 + d13                             = 0xe3
C4 : d13 + d14                             = 0xda
C5 : d14 + d15                             = 0x9c
C6 : d16 + d17                             = 0xce
C7 : d17 + d18                             = 0xa5
C8 : d18 + d19                             = 0x74
C9 : d19 + d20                             = 0x71
C10: d20 + d21                             = 0x98
C11: d21 + d22                             = 0x94
C12: d22 + d23                             = 0x99
C13: d23 + d0                              = 0xa9
C14: d3  * d15                             = 0xc0
C15: d7  * d21                             = 0x83
C16: d11 * d19                             = 0x24
C17: d4 ^ d12 ^ d20                        = 0x00
C18: d2 ^ d10 ^ d18                        = 0x6c
C19: d0 + d4 + d8 + d12 + d16 + d20        = 0xc4
C20: d1 ^ d5 ^ d9 ^ d13 ^ d17 ^ d21        = 0x09
C21: d2 + d7 + d10 + d15 + d18 + d23       = 0xd9
C22: d3 ^ d6 ^ d11 ^ d14 ^ d19 ^ d22       = 0x0f
```

### Валидатор B — три проверки

```
d9 + d10   = 0xa8      (дубль C1)
d20        = d4 ^ d12  (дубль C17)
d12 + d13  = 0xe3      (дубль C3)
```

B ничего нового не добавляет — чистая мишура, дублирующая A.

### Собственно «распечатывание» конфига (`0x404333`)

```
digest    = SHA256(key)                       # 32 байта
keystream = SHA256(digest ‖ BE32(0))          # MGF1 на SHA-256
          ‖ SHA256(digest ‖ BE32(1)) ‖ ...    # обрезается до 47 байт
plaintext = ciphertext[0x405e40] XOR keystream
if SHA256(plaintext) == stored[0x405e20]:
    print(plaintext)        # конфиг/флаг
else:
    print("config sealed")
```

Важно: контрольный хэш на `0x405e20` — это `SHA256` от **расшифрованного**
конфига, а не от ключа. Поэтому «подобрать мимо» нельзя: нужен настоящий ключ.

## 5. Восстановление ключа

23 ограничения жёстко связывают 24 байта ключа (остаётся ~1 степень свободы),
а финальный SHA-гейт снимает её. Ставить `z3` не понадобилось: система решается
распространением. Если зафиксировать `d12`, `d16` и выбрать решения
произведений `d3` (C14), `d7` (C15), а `d9` отсечь по C16, то все остальные
байты **определяются однозначно**:

* цепочки сумм/XOR дают `d0, d10, d11, d13, d14, d15, d17..d23`;
* `d4` ← C17, `d2` ← C18, `d8` ← C19, `d1` ← C20;
* `d6` ← C22, затем `d5 = d6 ^ 0x07` ← C0.

Каждый алгебраически-валидный кандидат прогоняется через настоящий
SHA-256-гейт. Из **2304** кандидатов проходит ровно **один**.

### Солвер (чистый Python, без зависимостей)

```python
import hashlib, struct

data = open("cold-beacon", "rb").read()
at = lambda v, n: data[v - 0x400000 : v - 0x400000 + n]
ct, stored = at(0x405e40, 47), at(0x405e20, 32)

sha = lambda b: hashlib.sha256(b).digest()
def keystream(digest, n):
    ks, c = b"", 0
    while len(ks) < n:
        ks += sha(digest + struct.pack(">I", c)); c += 1
    return ks[:n]

def unseal(key):
    pt = bytes(c ^ k for c, k in zip(ct, keystream(sha(key), 47)))
    return (sha(pt) == stored), pt

M = 0xff
for d16 in range(256):
    d17=(0xce-d16)&M; d18=(d16-0x29)&M; d19=(0x9d-d16)&M
    d20=(d16-0x2c)&M; d21=(0xc4-d16)&M; d22=(d16-0x30)&M
    d23=(0xc9-d16)&M; d0=(d16-0x20)&M
    d7c=[x for x in range(256) if (x*d21)&M==0x83]        # C15
    if not d7c: continue
    for d12 in range(256):
        d13=(0xe3-d12)&M; d14=(d12-0x09)&M; d15=(0xa5-d12)&M
        d4=(d12^d20)&M
        d3c=[x for x in range(256) if (x*d15)&M==0xc0]    # C14
        if not d3c: continue
        d8=(0xc4-(d0+d4+d12+d16+d20))&M                   # C19
        for d9 in range(256):
            d10=(0xa8-d9)&M; d11=(d9-0x34)&M
            if (d11*d19)&M != 0x24: continue              # C16
            d2=(0x6c^d10^d18)&M                           # C18
            for d7 in d7c:
                if (d2+d7+d10+d15+d18+d23)&M != 0xd9: continue  # C21
                for d3 in d3c:
                    d6=(0x0f^d3^d11^d14^d19^d22)&M         # C22
                    d5=(d6^0x07)&M                          # C0
                    d1=(0x09^d5^d9^d13^d17^d21)&M           # C20
                    key=bytes([d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,d10,d11,d12,
                               d13,d14,d15,d16,d17,d18,d19,d20,d21,d22,d23])
                    ok, pt = unseal(key)
                    if ok:
                        print("KEY   :", key.decode())
                        print("CONFIG:", pt.decode())
```

Вывод:

```
KEY   : C0ldB34c0n::unl0ck::7a3f
CONFIG: hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}
```

## 6. Проверка на живом бинаре

```
$ ./cold-beacon 'C0ldB34c0n::unl0ck::7a3f'
hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}
$ ./cold-beacon 'wrongwrongwrongwrongwron'
config sealed
```

Статический разбор полностью совпал с рантаймом.

## 7. Итог

* Язык/защита: **Nim**, stripped, XOR-`0x5A` на строках, антиотладка через `TracerPid`.
* Ворота ключа: длина 24 + 23 алгебраических ограничения (валидатор A), B — дубль.
* Крипто: `keystream = MGF1-SHA256(SHA256(key))`, `plaintext = ct ⊕ keystream`,
  контроль целостности `SHA256(plaintext)`.
* Ключ восстановлен решением системы ограничений и фильтром по SHA-гейту.

**Флаг:** `hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}`
