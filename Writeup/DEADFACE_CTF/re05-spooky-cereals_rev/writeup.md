# Writeup: Spooky Cereals — The Greys

Oct 22, 2026 · @Demian

RE-таск на .NET с тремя слоями: XOR-упакованная полезная DLL, проверка пароля через MD5 и флаг, зашифрованный AES-256-CBC с ключом из PBKDF2. Итог: пароль `booberry` (любимые хлопья Греев — Boo Berry), флаг `deadface{Before_Consenting_to_Med_Exam_Ascertain_Destination_of_Finger!}`.

## Условие

Дан бинарь `re05.exe`, якобы снятый с разбившегося корабля «Греев». По легенде нужно выяснить их любимые «spooky cereals», чтобы «подружиться». За флэйвором прячется обычная RE-задача: найти проверочный секрет внутри программы и восстановить зашифрованный флаг.

- Вход: один исполняемый файл Windows.
- Цель: восстановить настоящий флаг.
- Формат флага: `deadface{...}` (пример в условии — не настоящий).

## Triage

Первый шаг — `file` и `strings`. `file` показывает, что это **PE32, .NET-сборка** (Mono/.Net assembly), консольное приложение. Значит, вместо ассемблера будем смотреть IL / CIL.

`strings` даёт сразу много подсказок:

- Имена `DllLoader`, `dllBytes`, `xorKey`, `Assembly.Load`, `Activator.CreateInstance`, `MethodInfo.Invoke` — классический **рефлективный загрузчик**: внутри спрятана вторая сборка, которую расшифровывают XOR-ом и грузят в память.
- Длинный блок вида `3A3A3A3A3A3A...` — это и есть зашифрованная DLL. Повторяющийся узор «3A» — явный признак короткого XOR-ключа поверх области нулей (PE-заголовок второй сборки начинается с длинного нулевого padding’а).

Вывод: задача многослойная — сначала распаковать внутреннюю DLL, потом реверсить её логику.

## Слой 1: распаковка XOR-DLL

Внешний `re05.exe` — класс `DllLoader`: он держит байты второй сборки (`dllBytes`), XOR-ит их ключом `xorKey` и грузит через `Assembly.Load` + `Invoke`. Ключ — два байта `"3A"` (т.е. `0x33 0x41`), что видно по тому, как область нулей превратилась в `3A3A3A...`.

Распаковка без запуска под Windows — находим начало зашифрованного `MZ` (после XOR даёт `0x4D 0x5A`) и декодируем блок:

```python
d = open('re05.exe','rb').read()
k = b'3A'
off = d.find(bytes.fromhex('0c69d133'))   # начало заXORенной DLL
blob = bytes(d[off+i] ^ k[i % 2] for i in range(6656))
open('inner.dll','wb').write(blob)
```

На выходе — валидный `PE32 DLL (.NET assembly)`, `DLLPayload.dll`. Это и есть второй слой.

## Слой 2: логика проверки

У внутренней DLL говорящие строки и имена методов: `MyNamespace.MyClass`, поля `correctHash` и `encryptedFlag`, методы `CalculateMD5Hash`, `CompareByteArrays`, `DecryptAES`, а также `Rfc2898DeriveBytes`, `AES`, `CipherMode`, `PaddingMode`. Строка `thegreysarecomin` (ровно 16 символов) — явно соль/IV.

Разбор IL (без внешних декомпиляторов — сети не было, метаданные читались вручную) даёт такую логику `Main`:

1. Прочитать ввод пользователя (`Enter password:`).
2. `CalculateMD5Hash(input)` и сравнить с зашитым `correctHash` через `CompareByteArrays`.
3. Если совпало — `DecryptAES(encryptedFlag, input + input)` и вывести `Decrypted flag: {0}`.
4. Иначе — `Access Denied`.

Ключевые детали `DecryptAES` из IL: `set_KeySize(256)`, `set_Mode(CBC)`, `set_Padding(PKCS7)`, `Rfc2898DeriveBytes(password, salt, 1000)` — т.е. **PBKDF2 с 1000 итераций** (HMAC-SHA1 по умолчанию в .NET), из него `GetBytes(32)` на ключ. Важный момент: пароль для PBKDF2 — это `input + input` (ввод, склеенный сам с собой), а не просто ввод.

## Извлечение данных

Поля `correctHash` и `encryptedFlag` — это `static`-массивы, инициализируемые через `RuntimeHelpers.InitializeArray`, т.е. их байты лежат в секции `.sdata`. В метаданных видны два `$ArrayType`: **16 байт** (`correctHash` — длина MD5) и **80 байт** (`encryptedFlag`).

Разбираем PE-секции и читаем `.sdata` (96 байт = 16 + 80):

- `correctHash` (первые 16 байт): `7730e6666bec3dc346c105bd2012a813`
- `encryptedFlag` (остальные 80 байт): `c1921b0a...82a95c`

> ⚠️ Главная ловушка таска: легко взять все 96 байт за шифртекст. Но первые 16 — это MD5-хеш, а не часть флага. Если спутать, то при расшифровке «поедут» два первых блока вместо одного.

## Подбор пароля

Ключ AES выводится из пароля, поэтому обойти проверку нельзя — пароль нужен по-настоящему. У нас есть его MD5: `7730e6666bec3dc346c105bd2012a813`.

Тема таска — «любимые spooky cereals», поэтому строим тематический словарь из названий хлопьев (тем более среди «spooky» брендов есть Count Chocula, Franken Berry, Boo Berry) и проверяем MD5:

```python
import hashlib
h = '7730e6666bec3dc346c105bd2012a813'
for w in ['booberry','frankenberry','countchocula','trix','frootloops', ...]:
    for v in {w, w.lower(), w.replace(' ',''), w.capitalize()}:
        if hashlib.md5(v.encode()).hexdigest() == h:
            print('FOUND:', v)
# -> FOUND: booberry
```

Пароль — `booberry`. Это и есть ответ на вопрос условия: любимые хлопья Греев — **Boo Berry**.

## Расшифровка флага

Схема: AES-256-CBC + PKCS7, ключ = `PBKDF2-HMAC-SHA1(password, salt, 1000)[:32]`, где `password = "booberry" + "booberry"` и `salt = b"thegreysarecomin"`.

Первая попытка (IV из продолжения PBKDF2, `GetBytes(16)` после ключа) даёт **читаемый хвост, но битый первый блок**: `...Consenting_to_Med_Exam_Ascertain_Destination_of_Finger!}`. Это классический признак CBC: ключ верный (блоки 2+ читаются), а вот **IV неверный** — портится ровно первый 16-байтный блок.

Перебираем кандидаты IV (нули, соль, хеш, первые байты ключа). Срабатывает **IV = сама соль** `thegreysarecomin` — первый блок декодируется в `deadface{Before_`. Это типичный антипаттерн — соль и IV совпадают.

## Флаг и скрипт-решение

Полный solver от распаковки до флага:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# 1) распаковка внутренней DLL (XOR ключом '3A') — см. Слой 1
# 2) данные из .sdata:
sdata = bytes.fromhex(
  '7730e6666bec3dc346c105bd2012a813'            # correctHash (MD5), 16 байт
  'c1921b0a5c08b1073e69a57d290cdad6'            # encryptedFlag (80 байт)...
  'bb6a969e7bc670293969376c41d89def'
  '7e918e084aade130519c8b7a4584932a'
  '77d5d4deb9958e389cf7c5ba00629e62'
  '86e002840e3a5ed43d95c61ecc82a95c')
ct = sdata[16:]                                  # отбрасываем 16-байтный MD5

salt = b'thegreysarecomin'
pw   = b'booberry' * 2                            # input + input
key  = PBKDF2HMAC(hashes.SHA1(), 32, salt, 1000).derive(pw)
iv   = salt                                      # IV == salt

c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
p = c.update(ct) + c.finalize()
print(p[:-p[-1]].decode())                        # снимаем PKCS7
```

Результат:

```
deadface{Before_Consenting_to_Med_Exam_Ascertain_Destination_of_Finger!}
```

## Выводы

Чему учит таск:

- **.NET реверсится на уровне IL.** Даже без dnSpy/ILSpy можно разобрать метаданные и CIL вручную — имена методов и строки почти всё рассказывают.
- **Многослойность не равно стойкость.** XOR-упаковка с коротким ключом палится по узору в области нулей (known-plaintext — `MZ`).
- **Слабый KDF и предсказуемый пароль.** MD5 без соли + короткий тематический пароль = мгновенный подбор по словарю.
- **Не путать хеш и шифртекст.** Два массива лежат рядом в `.sdata`; длины `$ArrayType` (16 и 80) помогают разделить их.
- **IV == salt.** Частый антипаттерн: когда блоки 2+ читаются, а первый — нет, дело почти всегда в IV.

Итог: флаг `deadface{Before_Consenting_to_Med_Exam_Ascertain_Destination_of_Finger!}`, любимые хлопья Греев — Boo Berry.
