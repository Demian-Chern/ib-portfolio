# Baby Crypto — Writeup

**Флаг:** `FortID{St0p_B31ng_Cr3at1v3_With_N0nc3s_0r_You'll_R3gre7_17_9219f49beb}`

## Описание сервиса

Сервис представляет собой простое хранилище секретов ("vault"), работающее поверх AES в режиме CTR. При старте генерируется случайный ключ, флаг сразу кладётся в хранилище как первый секрет (`Secret #0`). Пользователь может:

1. Добавлять свои секреты в хранилище.
2. Экспортировать всё хранилище в виде JSON (hex-шифротексты).
3. Выйти.

```python
class Cipher:
    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=plaintext[:8])
        return cipher.encrypt(plaintext)
```

## Уязвимость

Ключевая проблема — в функции шифрования:

```python
cipher = AES.new(self.key, AES.MODE_CTR, nonce=plaintext[:8])
```

**Nonce берётся из первых 8 байт самого открытого текста**, а не генерируется случайно. При этом ключ AES один и тот же на протяжении всей сессии (`self.key` создаётся один раз в `Vault.__init__`).

Это классическая и критическая ошибка использования потокового шифра. В AES-CTR шифротекст вычисляется как:

```
ciphertext = plaintext XOR keystream
keystream  = E(key, nonce || counter)
```

Если у двух сообщений совпадают `(key, nonce)`, то у них будет **идентичный keystream**. А значит шифротексты можно связать друг с другом через XOR, вообще не зная ключа:

```
ct1 XOR ct2 = pt1 XOR pt2
```

Более того, если нам известен полный plaintext одного из двух сообщений, мы можем восстановить keystream напрямую:

```
keystream = ct XOR known_plaintext
```

и применить его к шифротексту второго (неизвестного) сообщения.

## Эксплуатация

### 1. Известный префикс флага

Формат флага фиксирован — `FortID{...}`. Значит первые 7 байт флага (`FortID{`) уже известны. Поскольку nonce — это ровно первые **8** байт plaintext, не хватает всего одного символа, чтобы знать nonce флага целиком.

### 2. Брутфорс 8-го байта

Перебираем все кандидаты на 8-й символ флага (`FortID{X`), отправляя их как собственные секреты через пункт меню `1`. После экспорта сравниваем первые 8 байт каждого полученного шифротекста с первыми 8 байтами шифротекста флага (`Secret #0`):

```python
for i, guess in enumerate(guesses, start=1):
    ct = bytes.fromhex(data[f"Secret #{i}"])
    if ct[:8] == flag_nonce_ct:
        found_char = guess[-1]
        break
```

Совпадение первых 8 байт шифротекста означает совпадение nonce → найден правильный 8-й символ флага.

### 3. Восстановление keystream

Зная теперь 8-байтовый nonce флага (`FortID{X`), отправляем собственный секрет с **тем же префиксом** и известным "хвостом" (например, много символов `A`), достаточно длинным, чтобы перекрыть всю длину флага:

```python
our_plain = known_prefix + "A" * pad_len
send_secret(io, our_plain)
```

Так как nonce совпадает — keystream у нашего сообщения и у флага идентичен. Вычисляем его:

```python
keystream = bytes(a ^ b for a, b in zip(our_ct, our_plain_bytes))
```

### 4. Расшифровка флага

Накладываем восстановленный keystream на шифротекст флага:

```python
recovered = bytes(a ^ b for a, b in zip(flag_ct, keystream))
```

Получаем флаг в открытом виде.

## Эксплойт (полный скрипт)

```python
#!/usr/bin/env python3
from pwn import *
import string
import json
import re

HOST = "example.fortidctf.com"
PORT = 1337
USE_SSL = True

CHARSET = string.ascii_letters + string.digits + "_-"
PROMPT = b"> "

def send_menu(io, choice):
    io.sendline(choice.encode())

def send_secret(io, secret):
    send_menu(io, "1")
    io.recvuntil(b"Enter secret: ")
    io.sendline(secret.encode())
    io.recvuntil(PROMPT)

def do_export(io):
    send_menu(io, "2")
    chunk = io.recvuntil(PROMPT)
    text = chunk.decode(errors="replace")
    m = re.search(r"\{.*\}", text)
    if not m:
        raise RuntimeError(f"no json in: {text!r}")
    return json.loads(m.group(0))

def main():
    io = remote(HOST, PORT, ssl=USE_SSL)
    io.recvuntil(PROMPT)

    # Забираем шифротекст флага (всегда Secret #0)
    data = do_export(io)
    flag_ct = bytes.fromhex(data["Secret #0"])
    flag_nonce_ct = flag_ct[:8]

    # Брутфорсим 8-й байт флага
    prefix = "FortID{"
    guesses = []
    for c in CHARSET:
        guess = prefix + c
        send_secret(io, guess)
        guesses.append(guess)

    data = do_export(io)
    found_char = None
    for i, guess in enumerate(guesses, start=1):
        ct = bytes.fromhex(data[f"Secret #{i}"])
        if ct[:8] == flag_nonce_ct:
            found_char = guess[-1]
            break

    known_prefix = prefix + found_char

    # Отправляем секрет с тем же nonce и известным хвостом
    pad_len = 200
    our_plain = known_prefix + "A" * pad_len
    send_secret(io, our_plain)

    data = do_export(io)
    our_ct = bytes.fromhex(data[f"Secret #{len(guesses) + 1}"])

    # Восстанавливаем keystream и расшифровываем флаг
    keystream = bytes(a ^ b for a, b in zip(our_ct, our_plain.encode()))
    recovered = bytes(a ^ b for a, b in zip(flag_ct, keystream))

    end = recovered.index(b"}") + 1
    print("FLAG:", recovered[:end].decode())

    io.close()

if __name__ == "__main__":
    main()
```

## Выводы

- **Nonce в потоковых шифрах (CTR, OFB, CFB, или в stream-ciphers вроде ChaCha20/RC4) никогда не должен зависеть от открытого текста** и не должен повторяться при одном и том же ключе.
- Повторное использование пары `(key, nonce)` в AES-CTR полностью ломает конфиденциальность шифра, независимо от стойкости самого AES — атакующему для расшифровки не нужен ключ, достаточно знать plaintext одного из сообщений с тем же nonce.
- Правильный подход: генерировать nonce случайно (`get_random_bytes`) или использовать монотонный счётчик, никак не связанный с содержимым сообщения.

## Инструменты

- `pwntools` — для взаимодействия с сервисом через TLS-сокет (`remote(..., ssl=True)`, аналог `ncat --ssl`).
