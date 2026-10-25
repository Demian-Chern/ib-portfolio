# License Validation Suite — Writeup

**Категория:** Reverse Engineering
**Файл:** `License_Validation_Suite_1` (ELF 64-bit, PIE, stripped)
**Флаг:** `flag{GDB_Runtime_Insights}`

---

## 1. Разведка

```
$ file lvs
ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a3fb7f…, stripped
```

Бинарник динамический, PIE, stripped. Запуск показывает приглашение ввести лицензионный ключ:

```
==================================================
            License Validation Suite
==================================================

Enter License Key: ____
```

Правильный ключ → `[SUCCESS] Key verified!`
Неправильный → `[ERROR] Invalid license key, potential fraud has been detected`

### Импорты и строки

```
$ strings lvs
...
ptrace        <-- анти-отладка
mmap / munmap <-- буфер под генерацию ключа в рантайме
fgets / strcspn / strlen
Enter License Key:
[SUCCESS] Key verified!
[ERROR] Invalid license key, potential fraud has been detected
```

Три важных импорта сразу задают тон:

- `ptrace` — почти наверняка анти-дебаг (`PTRACE_TRACEME`).
- `mmap` / `munmap` — ключ не лежит в данных в открытом виде, он **собирается на лету** в выделенном буфере.
- `strcspn` — классический приём «обрезать `\n`» после `fgets`.

Ключа в `strings` нет — значит, сравнение идёт не со статической строкой, а с вычисленным значением.

---

## 2. Статический анализ

Точка интереса — функция по адресу `0x1249` (настоящий `main`, переданный в `__libc_start_main`). Дизассемблируем:

```
objdump -d -M intel lvs
```

### 2.1. Выделение буфера и анти-отладка

```asm
mmap(0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0)
mov    rbx, rax                 ; rbx = буфер под ключ

; ptrace(PTRACE_TRACEME, 0, 0, 0)
mov    eax, 0x0                 ; request = 0 = PTRACE_TRACEME
call   ptrace
neg    rax                      ; 0 -> 0 (CF=0);  -1 -> 1 (CF=1)
sbb    r8b, r8b                 ; r8b = -CF  => 0x00 или 0xFF
and    r8d, 0x5a                ; => 0x00 (чисто) или 0x5a (под отладкой)
...
add    r8d, 0x37                ; r8d = 0x37 (чисто) ИЛИ 0x91 (под отладкой)
lea    r9, [rip+0xe43]          ; r9 -> зашифрованные байты @ 0x2120
```

Суть: результат `ptrace` превращается в число `r8d`:

| Ситуация | `ptrace` | `r8d` |
|---|---|---|
| Без отладчика | `0` | **`0x37`** |
| Под отладчиком | `-1` | `0x91` |

Это число — **начальное слагаемое генератора ключа**. Значит, под отладчиком весь ключ сгенерируется по-другому.

### 2.2. Генерация «правильного» ключа (26 байт)

```asm
mov    eax, 0xffffffa5          ; стартовое состояние
mov    esi, 0x0
xor    rdx, rdx
loop:
  lea  edi, [r8+rsi*1]          ; edi = r8d + esi
  mov  ecx, eax
  shl  ecx, 0x5
  sub  ecx, eax                 ; ecx = eax*31   (eax<<5 - eax)
  lea  eax, [rdi+rcx*1]         ; eax = (r8d+esi) + eax*31
  rol  al, 0x3                  ; поворот младшего байта
  xor  al, [r9+rdx*1]           ; ^ зашифрованный байт
  xor  eax, 0xffffffc7          ; ^ 0xC7 (младший байт участвует в выводе)
  mov  [rbx+rdx*1], al          ; key[i] = al
  add  rdx, 1
  add  esi, 0x11                ; esi += 17
  cmp  rdx, 0x1a                ; 26 итераций
  jne  loop
mov    byte [rbx+0x1a], 0x0     ; null-терминатор
```

Ключевые детали:

- Состояние `eax` **переносится между итерациями** целиком (32 бита), поэтому важно считать по-настоящему, а не только младший байт.
- `eax*31` реализовано как `(eax<<5) - eax`.
- `esi` растёт на `0x11` каждый шаг — «соль» от индекса.
- Длина ключа — ровно **26** байт.

### 2.3. Сравнение с вводом

```asm
printf("Enter License Key: ")
fgets(buf, 0x80, stdin)
strcspn(buf, "\n"); buf[n] = 0        ; срезали перевод строки
strlen(buf); cmp rax, 0x1a
setne  bpl                            ; bpl = (len != 26)

; посимвольный xor-diff
loop:
  movzx edx, byte [rbx+rax]           ; expected[i]
  xor   dl,  byte [rsp+rax]           ; ^ input[i]
  or    ebp, edx                      ; накапливаем расхождения
  inc   rax
  cmp   rax, 0x1a
  jne   loop

test   bpl, bpl
jne    FAIL                           ; хоть один байт не совпал / длина != 26
-> SUCCESS
```

Проверка — константное время по сути: аккумулируется OR всех `expected[i] ^ input[i]` плюс флаг длины. Ноль → успех.

---

## 3. Ловушка с GDB

Подсказка в задании советовала «подключить GDB для большей видимости процесса исполнения». Это **ложный след**.

Если поставить брейкпоинт и подсмотреть содержимое буфера под отладчиком, `ptrace(PTRACE_TRACEME)` вернёт `-1` → `r8d = 0x91` → сгенерируется **другой ключ** (мусор). Сам флаг (`GDB_Runtime_Insights`) намекает на этот трюк.

Правильные пути:

1. **Статически** посчитать ключ с `r8d = 0x37`.
2. Нейтрализовать `ptrace`:
   - `LD_PRELOAD` с заглушкой `ptrace`, возвращающей `0`;
   - в GDB: `catch syscall ptrace` / `set $rax=0` после вызова, либо патч байт так, чтобы в `r8d` всегда было `0x37`.

---

## 4. Solve-скрипт

Эмулируем цикл генерации на Python с `r8d = 0x37`. Зашифрованные байты берём по виртуальному адресу `0x2120`.

```python
import struct

data = open('lvs', 'rb').read()

# map vaddr -> file offset через program headers
e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum     = struct.unpack_from('<H', data, 0x38)[0]

def vaddr_to_off(v):
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if struct.unpack_from('<I', data, off)[0] != 1:   # PT_LOAD
            continue
        p_offset = struct.unpack_from('<Q', data, off + 0x08)[0]
        p_vaddr  = struct.unpack_from('<Q', data, off + 0x10)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 0x20)[0]
        if p_vaddr <= v < p_vaddr + p_filesz:
            return p_offset + (v - p_vaddr)
    raise ValueError("vaddr not found")

enc = data[vaddr_to_off(0x2120):][:26]

def gen(r8d):
    eax, esi, out = 0xffffffa5, 0, []
    for i in range(26):
        edi = (r8d + esi) & 0xffffffff
        ecx = ((eax << 5) - eax) & 0xffffffff          # eax*31
        eax = (edi + ecx) & 0xffffffff
        al  = eax & 0xff
        al  = ((al << 3) | (al >> 5)) & 0xff           # rol al,3
        eax = (eax & 0xffffff00) | al
        al  = (eax & 0xff) ^ enc[i]                    # xor al, enc[i]
        eax = (eax & 0xffffff00) | al
        eax ^= 0xffffffc7                              # xor eax, 0xC7
        out.append(eax & 0xff)
        esi = (esi + 0x11) & 0xffffffff
    return bytes(out)

print("KEY :", gen(0x37))      # без отладчика -> верный
print("TRAP:", gen(0x91))      # под отладчиком -> мусор
```

Вывод:

```
enc @0x2120: 30becde91b0b32d2751fcc4119af4ce98c40abd26d3a9e016ad4
KEY : b'flag{GDB_Runtime_Insights}'
TRAP: b'\x93\x02\x85\xd0\xf4_6\x81wD\xb0b\x07R\xe0\xab\xf9I\xb8\xf5.\xb9*\xb7?\xcd'
```

Проверка на живом бинарнике (без отладчика):

```
$ printf 'flag{GDB_Runtime_Insights}\n' | ./lvs
...
Enter License Key: [SUCCESS] Key verified!
```

---

## 5. Флаг

```
flag{GDB_Runtime_Insights}
```

## Выводы

- Ключ генерировался в рантайме в RWX-буфере, а не хранился в данных → `strings` ничего не даёт.
- `ptrace(PTRACE_TRACEME)` подмешан в генератор как арифметическая константа, так что наивная отладка ломает результат.
- Самый надёжный подход — вытащить алгоритм и зашифрованные байты и пересчитать ключ оффлайн, либо обойти `ptrace` перед снятием дампа.
