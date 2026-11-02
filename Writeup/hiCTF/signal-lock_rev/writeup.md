# Writeup: `signal_lock` — реверс BEAM-модуля (hiCTF)

**Категория:** Reverse Engineering (Erlang / BEAM)
**Файл:** `signal_lock.beam` (скомпилированный, stripped, без исходников)
**Цель:** восстановить единственный токен, который принимает валидатор `signal_lock:verify/1`; при приёме возвращается флаг `{ok, <<"hiCTF{...}">>}`.

## TL;DR

| | |
|---|---|
| **Токен** | 8-байтовый бинарь `<<"g4m30v3r">>` (hex `67346D3330763372`) |
| **Вызов** | `signal_lock:verify(<<"g4m30v3r">>).` |
| **Флаг** | `hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}` |

Проверка внутри модуля и расшифровка флага — две независимые функции от одного и того же `T`, и обе сходятся: `transform(T)` равен зашитой константе, а keystream, выведенный из `T`, расшифровывает встроенный шифротекст в корректный печатный флаг. Неверный `T` дал бы мусор на XOR — значит, токен однозначно верный.

---

## 1. Разведка

Файл по условию — «обычный BEAM-модуль», но `file` показал неожиданное:

```
$ file signal_lock.beam
signal_lock.beam: gzip compressed data, from Unix, original size modulo 2^32 1624
```

То есть `.beam` завёрнут в gzip. Распаковываем — и получаем настоящий BEAM (магия `FOR1...BEAM`):

```
$ gunzip -c signal_lock.beam > signal_lock_real.beam
$ file signal_lock_real.beam
signal_lock_real.beam: Erlang BEAM file
```

В заголовке видно и путь к исходнику сборки — `build/signal_lock.erl`.

> Запустить `erl -pa .` в песочнице не вышло (нет доступа к apt-зеркалам и к `builds.hex.pm` через прокси), поэтому весь разбор делался статически: парсинг чанков BEAM и ручной дизассемблер на Python. Для финальной проверки `signal_lock:verify(<<"g4m30v3r">>)` достаточно любого OTP ≥ 26.

## 2. Структура BEAM

BEAM — это IFF-подобный контейнер (`FOR1 <size> BEAM <chunks...>`). Распарсив чанки, получаем:

```
CHUNKS: ['Line', 'Type', 'AtU8', 'Code', 'StrT', 'ImpT', 'ExpT', 'LitT', 'Meta']
```

### 2.1. Таблица атомов (`AtU8`)

Атомы фактически раскрывают весь алгоритм ещё до чтения байткода:

```
verify, byte_size, no_fail, ensure_exactly, integer, ok,
transform, bxor, *, band, +, rotl, bsl, bsr, bor,
unlock, binary_to_list, lists, zip, list_to_binary,
keystream, binary, part, sha256, crypto, hash,
private_append, all, cipher
```

Видно: проверка длины (`ensure_exactly`), арифметическое перемешивание (`bxor/*/band/+`), ротация (`rotl` через `bsl/bsr/bor`), генерация потока ключа (`keystream`) на базе `crypto:hash(sha256, ...)`, и XOR-«шифр» (`cipher`/`unlock` через `lists:zip` + list comprehension).

### 2.2. Импорты (`ImpT`)

```
erlang:byte_size/1   erlang:bxor/2   erlang:*/2    erlang:band/2
erlang:+/2           erlang:bsl/2    erlang:bsr/2  erlang:bor/2
erlang:binary_to_list/1   lists:zip/2   erlang:list_to_binary/1
binary:part/3        crypto:hash/2
```

### 2.3. Литералы (`LitT`, zlib-сжатый)

Три литерала (в External Term Format):

| # | значение |
|---|----------|
| 0 | `{error, locked}` |
| 1 | `{error, bad_token}` |
| 2 | бинарь на **48 байт** — шифротекст: `f3a78b575b93c60be646d9eefd1f0aa0ac5ac53a2b0107f1a5c84adf4d989dc06c09680db73f54ad89bdd8ae0530c27b` |

Все остальные константы (длина, целевое значение, множители) — не в литералах, а инлайном в байткоде. Значит, нужен дизассемблер.

## 3. Дизассемблер

Чанк `Code` разбирается стандартно: заголовок (`sub_size`, версия, `opcode_max`, число меток/функций), дальше — инструкции. Каждый опкод имеет фиксированную арность (таблица `genop.tab`), операнды — в compact term encoding (теги `u/i/a/x/y/f/h` + расширенные `z`: list, alloc-list, literal, typed-register).

Ключевые места дизассемблированного `verify/1`:

```erlang
label 2  %% verify/1
  is_binary      L4, x0                     %% не бинарь -> {error,bad_token}
  byte_size(x0) -> x1
  is_eq_exact    L4, x1, 8                   %% длина != 8 -> {error,bad_token}
  bs_start_match4 no_fail, x0
  bs_match       [integer, size=64, x2]      %% T = <<x0:64/big>>  (8 байт -> 64-битный int)
  move x2 -> y0                              %% сохранить T
  call transform/1                           %% transform(T) -> x0
  is_eq_exact    L3, x0, 12675316763487955908  %% != CONST -> L3 {error,locked}
  move y0 -> x0                              %% x0 = T
  call unlock/1                              %% unlock(T) -> флаг
  put_tuple2     {ok, x0}
  return
```

Итак, токен — это **ровно 8 байт**, читаемые как 64-битное big-endian целое `T`, и приём происходит тогда и только тогда, когда `transform(T) == 12675316763487955908`.

## 4. Разбор алгоритма

### 4.1. `transform/1` — обратимая перестановка на 64 битах

```erlang
transform(X) ->
    a = (X bxor 16#A5A5A5A55A5A5A5A) band 16#FFFFFFFFFFFFFFFF,
    b = (a *    16#9E3779B97F4A7C15) band 16#FFFFFFFFFFFFFFFF,   %% golden ratio
    c = rotl64(b, 29),
    d = (c +    16#0123456789ABCDEF) band 16#FFFFFFFFFFFFFFFF.
```

`rotl/2` в байткоде специализирован константой 29 (`(V bsl 29) bor (V bsr 35)`, маска 64 бита) — обычный left-rotate.

Все четыре шага — биекции на `Z/2^64`:

* `xor C1` — обратима (ещё раз xor);
* `* C2` — обратима, т.к. `C2 = 0x9E3779B97F4A7C15` нечётное (есть обратное по модулю 2⁶⁴);
* `rotl 29` — обратима (`rotl 35`);
* `+ C3` — обратима (вычитание).

Поэтому брутфорс не нужен — `T` восстанавливается прямой инверсией.

### 4.2. `keystream/2` + `unlock/1` — выдача флага

```erlang
keystream(Seed, Len) -> keystream(Seed, Len, 0, <<>>).
keystream(Seed, Len, Ctr, Acc) when byte_size(Acc) >= Len ->
    binary:part(Acc, 0, Len);
keystream(Seed, Len, Ctr, Acc) ->
    Block  = <<Seed:64, Ctr:32>>,                 %% 12 байт
    Digest = crypto:hash(sha256, Block),          %% 32 байта
    keystream(Seed, Len, Ctr+1, <<Acc/binary, Digest/binary>>).

unlock(T) ->
    CT = cipher(),                                %% 48-байтовый литерал
    KS = keystream(T, byte_size(CT)),             %% 48 байт
    list_to_binary([C bxor K || {C,K} <- lists:zip(
                       binary_to_list(CT), binary_to_list(KS))]).
```

То есть keystream в counter-режиме:
`KS = ( sha256(<<T:64,0:32>>) ++ sha256(<<T:64,1:32>>) )[:48]`,
а флаг — это `CT XOR KS`.

## 5. Инверсия и восстановление токена

```python
MASK = (1<<64)-1
C1, C2, C3 = 0xA5A5A5A55A5A5A5A, 0x9E3779B97F4A7C15, 0x0123456789ABCDEF
D = 12675316763487955908

def rotl64(v,n): n&=63; return ((v<<n)|(v>>(64-n))) & MASK
def modinv_pow2_64(a):                  # обратное нечётного a по модулю 2^64 (Ньютон)
    x=1
    for _ in range(6): x=(x*(2-a*x))&MASK
    return x

c = (D - C3) & MASK
b = rotl64(c, 35)                       # обратно к rotl 29
a = (b * modinv_pow2_64(C2)) & MASK
T = (a ^ C1) & MASK                     # = 0x67346D3330763372
token = T.to_bytes(8,'big')            # b"g4m30v3r"
```

Проверка вперёд: `transform(T) == D` → `True`.

Расшифровка:

```python
import hashlib, struct
def keystream(seed, n):
    out=b''; ctr=0
    while len(out)<n:
        out += hashlib.sha256(struct.pack('>Q',seed)+struct.pack('>I',ctr)).digest(); ctr+=1
    return out[:n]

ct   = bytes.fromhex("f3a78b575b93c60be646d9eefd1f0aa0ac5ac53a2b0107f1a5c84adf4d989dc06c09680db73f54ad89bdd8ae0530c27b")
flag = bytes(x^y for x,y in zip(ct, keystream(T, len(ct))))
# -> b"hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}"
```

## 6. Результат

```erlang
1> signal_lock:verify(<<"g4m30v3r">>).
{ok,<<"hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}">>}
```

**Токен:** `g4m30v3r` (`<<16#67346D3330763372:64>>`)
**Флаг:** `hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}`

## 7. Выводы

* Обёртка gzip над `.beam` — косметика; настоящий формат виден по магии `FOR1...BEAM`.
* Таблицы `AtU8` / `ImpT` / `LitT` в stripped-модуле всё равно выдают почти всю логику — имена функций, BIF-ов и константы-литералы.
* Самоуверенная «криптография на коленке»: обратимое перемешивание в качестве проверки (`transform`) означает, что секрет восстанавливается аналитически, без перебора 2⁶⁴ вариантов. Нечётный множитель (golden ratio) обратим по модулю 2⁶⁴ — классическая ловушка.
* `keystream = sha256(seed‖counter)` — корректный приём, но ключ полностью определяется токеном, а токен утёк из слабой проверки — поэтому «анти-чит» раскрывается целиком из одного оффлайн-билда.
