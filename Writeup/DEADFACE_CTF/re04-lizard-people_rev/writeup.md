# DEADFACE CTF — re04 (Lizard People): врайтап

Oct 22, 2026 · @Demian

## Условие и итог

Флаг: `deadface{Liz4rds_L0ve_Krampuffs_for_some_odd_reason...}`. Пароль `letmein`, но даже с ним программа отвечает «Access denied»: это и есть «гоча» из условия.

Дан `re04-win-x64.exe` (PE32+, Windows x64, консоль). Нужно найти пароль, ввести его и найти скрытые ловушки. Формат ответа: `deadface{...}`.

| Что | Значение |
| --- | --- |
| Пароль | `letmein` (MD5 `0d107d09f5bbe40cade3de5c71e9e9b7`) |
| Ловушка | аппаратный брейкпоинт Dr0 + векторный обработчик исключений |
| Ключ из обработчика | `0xd1cefa11badc0de5` |
| Шифр флага | xorshift64, 55 байт (0x37) |
| Флаг | `deadface{Liz4rds_L0ve_Krampuffs_for_some_odd_reason...}` |

## 1. Разведка

В строках бинарника нет ни флага, ни строки с ним, значит флаг зашифрован.

```bash
$ file re04.exe
re04.exe: PE32+ executable (console) x86-64, for MS Windows, 6 sections
$ strings re04.exe | grep -iE 'pass|access|dead'
On behalf of everyone here at the DEADFACE CTF, ...
What is the password:
Access granted. We are WORTHY!!!\n%s\n
Access denied.... we are unworthy...
```

Строка успеха печатает `%s`: флаг собирается в рантайме. Дизассемблируем (`objdump -d -M intel` или Ghidra/IDA) и идём от ссылки на строку `What is the password` — это `main` по адресу `0x140001120`.

## 2. Проверка пароля

Пароль хэшируется MD5 и сравнивается с константой; это MD5 слова `letmein`.

`main` читает до 128 байт через `fgets`, обрезает `\n` (`strcspn`) и инициализирует состояние константами MD5:

```nasm
mov DWORD PTR [rsp+0x50], 0x67452301
mov DWORD PTR [rsp+0x54], 0xefcdab89
mov DWORD PTR [rsp+0x58], 0x98badcfe
mov DWORD PTR [rsp+0x5c], 0x10325476
call 0x140001630        ; MD5_Update
call 0x1400014c0        ; MD5_Final
cmp  rax, [0x140018580] ; первые 8 байт эталонного хэша
cmp  rax, [0x140018588] ; вторые 8 байт
call 0x140001ad0        ; совпало -> функция успеха(пароль)
call 0x140001100        ; не совпало -> Access denied
```

Эталон по адресу `0x140018580`: `0d107d09f5bbe40cade3de5c71e9e9b7`. Любой поиск по MD5 (crackstation) или словарь rockyou сразу даёт `letmein`:

```bash
$ echo -n letmein | md5sum
0d107d09f5bbe40cade3de5c71e9e9b7  -
```

## 3. Гоча: аппаратный брейкпоинт + VEH

Даже с `letmein` функция успеха не выполняется: её перехватывает аппаратный брейкпоинт, а обработчик исключения уводит её в «Access denied».

До чтения пароля `main` делает три вещи:

1. Сохраняет адрес функции успеха `0x140001ad0` в глобальную переменную `0x140024aa8`.
2. Регистрирует векторный обработчик `0x140001000` через `AddVectoredExceptionHandler(1, ...)`.
3. Запускает поток `0x140001070`. Он приостанавливает главный поток, через `GetThreadContext`/`SetThreadContext` пишет `Dr0 = 0x140001ad0`, `Dr7 = 1` (брейкпоинт на исполнение) и возобновляет его.

Обработчик ловит именно этот брейкпоинт:

```nasm
cmp DWORD PTR [rax], 0x80000004      ; EXCEPTION_SINGLE_STEP?
test BYTE PTR [rdx+0x68], 1           ; Dr6.B0 — сработал Dr0?
cmp [rdx+0xf8], 0x140001ad0          ; RIP == функция успеха?
movabs rax, 0xd1cefa11badc0de5
mov [0x140024ab0], rax               ; ключ для расшифровки
mov [rdx+0xf8], 0x140001100          ; RIP -> Access denied
mov eax, -1                          ; EXCEPTION_CONTINUE_EXECUTION
```

&#91;embedded content: поток управления · аппаратный брейкпоинт перехватывает успех\]

Итог: при обычном запуске флаг не показывается никогда. Зато обработчик выдаёт ключ `0xd1cefa11badc0de5`, без которого флаг не расшифровать.

## 4. Расшифровка флага

Функция успеха `0x140001ad0` XOR-ит 55 байт с потоком xorshift64. Зерно строится из MD5 пароля и ключа из обработчика.

1. Считает MD5 пароля и берёт первые 8 байт как little-endian `u64`.
2. `seed = u64 XOR [0x140024ab0]`, где в глобальной переменной лежит ключ из VEH. Если вышел 0, берётся `0x9e3779b97f4a7c15` (`cmovne`).
3. На каждый байт: шаг xorshift64 (`x ^= x<<13; x ^= x>>7; x ^= x<<17`), затем `out[i] = (x & 0xff) ^ ct[i]`. Шифротекст лежит по адресу `0x1400185a0`, длина 0x37 = 55.
4. Считает MD5 результата и сравнивает с контрольным хэшем по адресу `0x140018590`. Совпало — печатает `Access granted. We are WORTHY!!!` и флаг.

Сам пароль для расшифровки не нужен: зерно зависит только от его MD5, а MD5 уже зашит в бинарь.

| Ключ в `0x140024ab0` | Результат | Контрольный MD5 |
| --- | --- | --- |
| `0` (VEH не сработал) | мусор | не совпал |
| `0xd1cefa11badc0de5` (ключ из VEH) | `deadface{Liz4rds_L0ve_Krampuffs_for_some_odd_reason...}` | совпал |

Первая строка — вторая ловушка: если просто занопить обработчик, ключ не запишется и флаг не соберётся.

## 5. Солвер и другие пути

Статическая расшифровка без запуска бинарника (адрес `0x1400185a0` = смещение в файле `0x16fa0`):

```python
import struct, hashlib

d = open('re04.exe', 'rb').read()
va = lambda v: v - 0x140018000 + 0x16a00   # .rdata: VA -> file offset

pw_md5 = d[va(0x140018580):va(0x140018590)]   # md5('letmein')
chk    = d[va(0x140018590):va(0x1400185a0)]   # md5 флага
ct     = d[va(0x1400185a0):va(0x1400185a0) + 0x37]

M = (1 << 64) - 1
s = struct.unpack('<Q', pw_md5[:8])[0] ^ 0xd1cefa11badc0de5
out = bytearray()
for c in ct:
    s ^= (s << 13) & M; s ^= s >> 7; s ^= (s << 17) & M
    out.append((s & 0xff) ^ c)

print(out.decode())
assert hashlib.md5(out).digest() == chk
```

```text
deadface{Liz4rds_L0ve_Krampuffs_for_some_odd_reason...}
```

Динамически под Windows:

- **x64dbg.** Ввести `letmein`, поставить программный брейкпоинт на `0x140001100`. Когда он сработает после VEH, ключ уже в `0x140024ab0`: перенести RIP на `0x140001ad5` (после первой инструкции, чтобы Dr0 не сработал снова), восстановив стек и `rcx` = буфер с паролем.
- **Патч.** В обработчике занопить запись RIP (`mov [rax+0xf8], rdx` по адресу `0x140001041`, 7 байт). Ключ пишется, исполнение продолжается в функции успеха (Dr6 сбрасывается, повторно брейкпоинт не ловится благодаря RF).

Не работает: просто пропатчить сравнение MD5 или выкинуть обработчик — без ключа из VEH получится мусор, и контрольный MD5 не сойдётся.
