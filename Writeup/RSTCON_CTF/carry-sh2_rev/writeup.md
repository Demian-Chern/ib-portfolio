# Carry — разбор crackme (SH-2)

Oct 25, 2026 · @Demian

## Задача

`carry` — ELF-исполняемый crackme под архитектуру **Renesas SuperH (SH-2)**.

Программа печатает приглашение `Carry the tide. Enter control key:`, читает строку со stdin и передаёт её в функцию `check`. При верном ключе выводит `Sluice aligned.`, иначе — `Out of phase.`

**Цель** — восстановить правильный control key (флаг).

## Разведка

Статический разбор, без запуска.

```
$ file carry
carry: ELF 32-bit LSB executable, Renesas SH, version 1 (SYSV),
       dynamically linked, interpreter /lib/ld-linux.so.2, not stripped
```

Архитектура — Renesas/SuperH, флаги `sh2`, порядок байт little-endian. Бинарник **не stripped** — имена функций и данных на месте.

Ключевые символы:

| Символ | Адрес | Назначение |
| --- | --- | --- |
| `check` | 0x400730 | проверка ключа (212 байт) |
| `main` | 0x400804 | ввод / вывод |
| `target` | 0x40095c | эталон, 38 байт |
| `target_len` | 0x400984 | длина = 38 |

Строки в `.rodata`: `Carry the tide. Enter control key:`, `Sluice aligned.`, `Out of phase.`

Содержимое `target` (38 байт):

```
cc e5 e7 d7 d2 dd e9 ed e7 e3 dc d7 d7 d5 c6 d2 e8 e2 cc
d4 e3 e5 e0 d7 d2 d7 d2 c8 d7 cd d1 d7 db db d7 e5 d8 e2
```

Все байты лежат в диапазоне 0xC6–0xED — явный признак, что это не сам ключ, а результат трансформации.

## Дизассемблирование SH-2

В окружении не оказалось дизассемблера для SH: системный `objdump` собран без этой архитектуры, а `capstone` / `radare2` поставить нельзя — PyPI и сеть закрыты.

Поэтому написал собственный декодер SH-2 — ISA очень регулярная:

- инструкции фиксированной ширины **16 бит**;
- в файле слова хранятся little-endian: `word = b[0] | (b[1] << 8)`;
- декодирование идёт по ниблам (старший нибл задаёт класс операции).

Корректность декодера подтвердил по узнаваемым паттернам:

- **пролог** `check`: `mov.l r14,@-r15` / `sts.l pr,@-r15` / `add #-16,r15` / `mov r15,r14`;
- **эпилог**: `lds.l @r15+,pr` / `mov.l @r15+,r14` / `rts` + `nop` в delay-slot;
- **литерал-пул** в хвосте функции: 32-битные константы `0x00400604` (адрес `strlen`) и `0x0040095c` (адрес `target`), подгружаемые через `mov.l @(disp,pc),rN`.

Всего в `check` — 106 инструкций.

## Анализ функции `check`

Сначала `check` требует `strlen(key) == 38`, затем в цикле сверяет бегущую сумму соседних байт с `target`. Локалки адресуются через фрейм `r14`: аккумулятор `acc` в `@(6,r14)`, временный байт `t` в `@(7,r14)`.

Аннотированное ядро цикла (SH-2):

```
mov   #38, r1
cmp/eq r1, len         ; strlen(key) == 38 ?
bt    body             ;   иначе return 0

mov   #90, r2
mov.b r2, @(6,r14)     ; acc = 90   (0x5A)

loop:                   ; i = 0..37
  mov.b @r1, r1         ; r1 = key[i]      (r1 = key + i)
  extu.b r1, r3         ; r3 = key[i] (0..255)
  mov.b @(6,r14), r0    ; r0 = acc
  add   r3, r2         ; r2 = acc + key[i]
  mov.b r2, @(7,r14)    ; t  = (acc + key[i]) & 0xFF

  mov.b @r1, r1         ; r1 = target[i]   (r1 = target + i)
  extu.b r1, r1
  cmp/eq r1, r2         ; t == target[i] ?
  bf    fail            ;   нет -> return 0

  mov.b @r1, r2         ; r2 = key[i]
  mov.b r2, @(6,r14)    ; acc = key[i]     <-- «carry»: перенос в следующий шаг
  add   #1, i
  cmp/ge len, i
  bf    loop            ; пока i < 38
```

В сумме логика сводится к:

```c
if (strlen(key) != 38) return 0;
uint8_t acc = 90;                  // 0x5A
for (int i = 0; i < 38; i++) {
    uint8_t t = acc + key[i];      // mod 256
    if (t != target[i]) return 0;
    acc = key[i];                  // перенос
}
return 1;
```

Это и есть «carry the tide»: каждый байт переносится в следующий шаг, и эталон оказывается суммой соседних байт ключа:

```latex
\begin{aligned}
\mathit{target}_0 &= (90 + \mathit{key}_0) \bmod 256 \\
\mathit{target}_i &= (\mathit{key}_{i-1} + \mathit{key}_i) \bmod 256, \quad i \ge 1
\end{aligned}
```

## Инверсия и солвер

Рекуррентность обратима напрямую — «unwinds in reverse». Зная `target` и seed = 90, восстанавливаем ключ побайтно:

```latex
\begin{aligned}
\mathit{key}_0 &= (\mathit{target}_0 - 90) \bmod 256 \\
\mathit{key}_i &= (\mathit{target}_i - \mathit{key}_{i-1}) \bmod 256, \quad i \ge 1
\end{aligned}
```

Скрипт-солвер на Python:

```python
target = bytes.fromhex(
    "cce5e7d7d2dde9ede7e3dcd7d7d5c6d2e8e2cc"
    "d4e3e5e0d7d2d7d2c8d7cdd1d7dbdbd7e5d8e2")

SEED = 90                      # 0x5A
key = bytearray(len(target))
acc = SEED
for i, tb in enumerate(target):
    key[i] = (tb - acc) & 0xFF
    acc = key[i]

print(key.decode())
# -> rstcon{running_sum_unwinds_in_reverse}
```

## Флаг

Ключ (control key):

```
rstcon{running_sum_unwinds_in_reverse}
```

Ровно 38 символов, все печатные. Проверил прямым прогоном алгоритма: все 38 сравнений с `target` совпадают, `check` возвращает 1 → `Sluice aligned.`

Запуск вживую под эмулятором SH (нужен sysroot с SH-версиями `ld-linux`/`libc`):

```
$ qemu-sh4 -L /path/to/sh4-sysroot ./carry
Carry the tide. Enter control key: rstcon{running_sum_unwinds_in_reverse}
Sluice aligned.
```
