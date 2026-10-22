# gaslightCTF — newjeans-is-five (crypto)

*(ранее в наших заметках числилась как "unidentified_aes" — задача была
решена, но без привязки к названию/условию; теперь сопоставлена.)*

## Категория
Crypto / Broken AES (custom round function)

## Дано
`chall.py` — урезанная самодельная реализация AES: `KeyExpansion`
присутствует, но `SubWord` — **identity** (`return word`, вместо реальной
S-box), а `SubBytes` аналогично не делает ничего (`return state`).
Остаются только **`ShiftRows`** и **`MixColumns`** на 9 раундов + финальный
`ShiftRows` — то есть вся "защита" сводится к чисто **линейным** (над
GF(2⁸)) преобразованиям без какой-либо подстановки и без XOR с раундовым
ключом внутри раундов.

Дано: известная пара `(plaintext, ciphertext)` и отдельный
`ciphertext` самого флага.

## Анализ

Описание задачи — каламбур: *"NewJeans is not NewJeans without any one of
its members. What is AES without one of its components?"* — намёк на то,
что убрали один из столпов AES (`SubBytes`/S-box), оставив голый линейный
слой.

Без S-box вся цепочка `ShiftRows → MixColumns`, повторённая 9 раз, плюс
финальный `ShiftRows` — это **линейное отображение** над 16-байтным блоком
(при фиксированном ключе эффективно сводится к `C = L(P) ⊕ K'`, где `L` —
известное, не зависящее от секрета линейное преобразование, а `K'` —
эффективный комбинированный ключевой шум). Из одной известной пары
`(plaintext, ciphertext)` можно вычислить этот эффективный `K'`:

```python
def find_K(plaintext, ciphertext):
    state = ToMatrix(plaintext)
    for _ in range(9):
        state = ShiftRows(state)
        state = MixColumns(state)
    state = ShiftRows(state)
    state = FromMatrix(state)
    return xor(bytes.fromhex(state), bytes.fromhex(ciphertext)).hex()
```

то есть `K' = L(P) ⊕ C`. Поскольку `L` не зависит от секретного ключа (а
только от самой структуры ShiftRows/MixColumns), **один и тот же `K'`**
действует для любого другого шифротекста, зашифрованного той же функцией —
в том числе для шифротекста флага. Остаётся обратить операцию:

```python
def recover_P(ciphertext, K):
    state = xor(bytes.fromhex(ciphertext), bytes.fromhex(K)).hex()
    state = ToMatrix(state)
    state = InvShiftRows(state)
    for _ in range(9):
        state = InvMixColumns(state)
        state = InvShiftRows(state)
    return FromMatrix(state)
```

`InvShiftRows`/`InvMixColumns` — точные обратные операции (обратная
перестановка строк, умножение на обратную MDS-матрицу `{0xe,0xb,0xd,0x9}`
в `GF(2⁸)`).

## Наш рабочий скрипт (`solve.py`)

Мы реализовали то же самое вручную (`ToMatrix`/`FromMatrix`,
`ShiftRows`/`InvShiftRows`, `GMul`, `MixColumns`/`InvMixColumns`, плюс
собственную "линейную дешифровку без ключа" `LinDec` — по сути то же
`recover_P`, но выведенное независимо) и на выходе получили строку
`newj34ns-nv-d!es` — на момент решения не было понятно, что это и есть
содержимое флага (без обёртки `gaslightCTF{...}`), так как не было связи
с конкретным заданием.

## Официальное решение (для сверки)

`official_solution.py` рядом — тот же алгоритм (`find_K` + `recover_P`),
но с явно зашитыми в файл `pt`/`ct` для вычисления `K`, и отдельным
`flag_ct` для самого флага. Оба независимых решения (наше и официальное)
сходятся к одной и той же открытой строке.

## Флаг

```
gaslightCTF{newj34ns-nv-d!es}
```

Статический флаг, подтверждён по `chall.yaml` (имя задачи в репозитории —
`newjeans-is-five`). Закрывает прежнюю запись "unidentified_aes" — скрипт
был рабочим с самого начала, просто не был подписан.

## Выводы / чеклист для похожих заданий

1. Если в "AES-подобном" шифре одна из стандартных стадий превращена в
   identity-функцию (`SubBytes`, `AddRoundKey` и т.п.) — весь шифр,
   скорее всего, стал **линейным**, и известного одного plaintext/
   ciphertext пара достаточно, чтобы вычислить эффективный "ключевой шум"
   и переиспользовать его для расшифровки любого другого сообщения той же
   длины, зашифрованного тем же (неизменным) ключом.
2. Названия/описания задач в crypto-CTF часто дают прямую подсказку на
   то, какой конкретно компонент алгоритма сломан или убран — стоит
   проверять это в первую очередь, до погружения в реализацию.
