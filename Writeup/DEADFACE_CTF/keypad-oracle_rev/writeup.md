# Keypad Oracle — DEADFACE CTF Writeup

Oct 22, 2026 · @Demian

## Обзор

Флаг: `deadface{your-pin-is-valid}`, PIN — **3719**. Категория — реверс (iOS-приложение, Mach-O ARM64, Swift).

Условие: дан `Keypad-Oracle.app` из пайплайна DEADFACE. Приложение просит ввести 4-значный PIN без повторяющихся цифр и выводит hex-строку. Нужно найти секретное сообщение.

Идея решения: восстановить алгоритм шифрования из дизассемблера, переписать его на Python и перебрать все 5040 допустимых PIN-ов.

## Разведка

Внутри архива вся логика лежит в `Keypad-Oracle.debug.dylib` (debug-сборка Xcode), а ключи — в `KeypadConfig.json`.

```
Keypad-Oracle.app/
├── Info.plist
├── KeypadConfig.json
├── Keypad-Oracle             # стаб-загрузчик
├── Keypad-Oracle.debug.dylib # Swift-код, ARM64
└── __preview.dylib
```

`KeypadConfig.json` содержит по 27 байт на каждую цифру 0–9:

```json
{
  "digits": {
    "0": "8e07513d09e6379a5b14f845137456c5f4974967c678c07e1a9025",
    "1": "d179fa8cf908d9ed599ab5967c4f8d362de70c1a791babc9b75bcc",
    ...
    "9": "5992f0ee2c8c682daa6038ef393108b28a40548fc97f99b33f1d88"
  }
}
```

`strings` по dylib даёт имена функций (символы не вырезаны):

- `PinCipherEngine.encode(pin:)`
- `PinCipherEngine.derive(seed:digit:position:)`
- `PinCipherEngine.rotateLeft(_:by:)`, `xor(_:_:)`
- свойства `outputLength`, `binarySalt`, `seedTable`
- строка «Enter a 4-digit PIN. Digits may not repeat.»

## Первая гипотеза (не сработала)

Длина ключей — 27 байт, ровно длина `deadface{...}` с коротким текстом. Первая мысль: флаг = XOR четырёх ключей цифр. Перебор всех 210 сочетаний C(10,4) не дал ни одной печатаемой строки — значит, ключи дополнительно преобразуются, и надо лезть в код.

## Дизассемблирование

Хватило `llvm-objdump -d` — сборка без оптимизаций, все константы видны прямо в `mov`. Ghidra/IDA тоже подойдут.

```
llvm-objdump -d --no-show-raw-insn Keypad-Oracle.debug.dylib > dis.txt
```

**`outputLength` (0x19d0)** — возвращает константу 27 (`mov w8, #0x1b`).

**`binarySalt` (0x19e4)** — массив из 28 байт, каждый пишется отдельной парой `mov`/`strb`:

```
3a 91 44 2f d0 18 6b c3 72 0e a9 5d 11 be
80 27 f4 66 39 9a 05 cc 70 1b 88 42 e1 53
```

**`encode(pin:)` (0x26d0)** — проверяет, что цифр 4, далее в цикле по `enumerated()`:

1. берёт ключ цифры из `seedTable` (то есть из JSON);
2. вызывает `derive(seed, digit, position)`;
3. XOR-ит результат в аккумулятор.

После цикла аккумулятор XOR-ится с `self+0x18` (`binarySalt`) и выводится через `toHexString()`. Важно: позиция цифры влияет на результат, поэтому перебирать надо размещения (5040), а не сочетания.

**`derive(seed:digit:position:)` (0x2f4c)** — цикл `i` от 0 до `outputLength` (читается из `[x20, #0x10]`, где x20 = `self`). Ключевые инструкции:

```
3200  sdiv/mul/subs        ; seed[i % seed.count]
3244  mov w8,#0x21 ; mul   ; (position + 1) * 33
332c  mov w8,#0x13 ; mul   ; digit * 19
3420  mov w8,#0x7  ; mul   ; i * 7
3528  eor / eor / eor      ; b ^ a ^ c ^ d
3590  sdiv #8              ; (digit + position + i) % 8
3668  bl rotateLeft
3694  mov w8,#0xb  ; mul   ; position * 11
37a0  eor                  ; v ^ (i + digit + position*11)
```

Все промежуточные значения приводятся к `UInt8` (`and #0xff` и проверки диапазона с трапом `brk`).

**`rotateLeft(_:by:)` (0x3be8)** — обычный циклический сдвиг байта: `(v << r) | (v >> (8 - r))`, `r & 7`.

## Восстановленный алгоритм и солвер

Для каждой цифры PIN (цифра `d`, позиция `p`) и каждого байта `i` выхода:

```latex
v_i = \mathrm{rol}\big(s_d[i] \oplus 33(p+1) \oplus 19d \oplus 7i,\ (d+p+i) \bmod 8\big) \oplus (i + d + 11p)
```

Итог: `out = derive(pin₀,0) ⊕ derive(pin₁,1) ⊕ derive(pin₂,2) ⊕ derive(pin₃,3) ⊕ salt`, все операции по модулю 256. Правильный PIN даёт ASCII-флаг, неверный — мусор. Критерий отбора при переборе — все 27 байт печатаемые.

```python
import json, itertools

d = {int(k): bytes.fromhex(v) for k, v in
     json.load(open('KeypadConfig.json'))['digits'].items()}
salt = bytes.fromhex('3a91442fd0186bc3720ea95d11be8027'
                     'f466399a05cc701b8842e153')

def rol(v, r):
    return ((v << r) | (v >> (8 - r))) & 0xff if r else v

def derive(seed, dg, pos):
    out = []
    for i in range(27):
        v = (seed[i % len(seed)] ^ ((pos + 1) * 33 & 0xff)
             ^ (dg * 19 & 0xff) ^ (i * 7 & 0xff))
        v = rol(v, (dg + pos + i) % 8)
        v ^= (i + dg + pos * 11) & 0xff
        out.append(v)
    return out

for pin in itertools.permutations(range(10), 4):
    acc = [0] * 27
    for pos, dg in enumerate(pin):
        acc = [a ^ b for a, b in zip(acc, derive(d[dg], dg, pos))]
    res = bytes(a ^ b for a, b in zip(acc, salt))
    if all(32 <= x < 127 for x in res):
        print(pin, res)
```

Вывод:

```
(3, 7, 1, 9) b'deadface{your-pin-is-valid}'
```

## Результат

PIN **3719** — единственный из 5040, дающий читаемый текст. Флаг:

```
deadface{your-pin-is-valid}
```

Проверить можно в симуляторе: при вводе 3719 приложение покажет hex `646561646661…`, который декодируется в флаг.

Что стоит запомнить:

- В iOS-сборках из Xcode (Debug) код лежит в `*.debug.dylib`, а основной бинарник — лишь загрузчик.
- Swift-символы в debug-сборке не вырезаны — имена функций сразу показывают структуру шифра.
- Данные из JSON — не всё: часть ключа (salt) зашита в код. Простая гипотеза «XOR ключей» без реверса не работает.
- Пространство PIN-ов маленькое (5040), так что после восстановления алгоритма перебор занимает доли секунды.
