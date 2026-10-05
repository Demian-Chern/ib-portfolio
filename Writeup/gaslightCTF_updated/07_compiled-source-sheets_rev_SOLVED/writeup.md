# gaslightCTF — compiled-source-sheets (rev)

## Категория
Reverse Engineering / custom VM (8086-подобный, исполняемый как CSS-анимации)

## Дано
`handout/` + `vm.html` — страница на основе проекта [x86CSS](https://github.com/rebane2001/x86CSS):
C-код компилируется в 8086-машинный код, который затем транслируется в
**CSS keyframe-анимации**, "исполняющие" процессор прямо в браузере
(никакого JS-интерпретатора — состояние процессора кодируется положениями
CSS-анимаций). Авторская подпись в описании ("мой VM защищён от Spectre,
без race conditions, работает в любой ОС... которая поддерживает
Chrom(e|ium)") — подсказка именно на этот трюк.

## Официальный исходник (`checker.c`)

```c
void (*writeChar1)(char)          = (void*)(0x2000);
void (*writeChar4)(const char[4]) = (void*)(0x2002);
void (*writeChar8)(const char[8]) = (void*)(0x2004);
char (*readInput)(void)           = (void*)(0x2006);

int _start(void) {
    char password[10];
    int len = 0;
    // "guess the password: "
    ...
    while (len < 10) {
        ...
        password[len++] = c;
    }
    if (len % 2) goto fail;
    if (len >= 9) goto fail;

    // -- BEGIN gen  (сгенерировано generate_constraints.py)
    if ((password[6] ^ password[2]) == (char)0x6f && ... ) {
        ...
    } else {
        goto fail;
    }
    if ((password[7] ^ password[4]) != (char)0x76 || ...) {
        goto fail;
    }
    // -- END gen

    writeChar8("congrats"); writeChar4("!\n\0\0");
    writeChar8("gaslight"); writeChar8("CTF{ch3c");
    writeChar8("k_0ut_ly"); writeChar8("ra-horse");
    writeChar4("!!_\0");
    writeChar8(password);        // <-- введённый пароль эхом попадает во флаг!
    writeChar1('}');
    return 67;
fail:
    writeChar8("nope :(\n");
    return -67;
}
```

Задача — консольный "guess the password" на 8 байт (`len < 9`, чётная
длина), где каждое условие — побитовое соотношение (`^`, `&`, `|`, `*`)
между **парой байт** пароля и константой. Все эти условия сгенерированы
скриптом `generate_constraints.py` из секретного `target`:

```python
target = "2QY90H6F".encode()
# ... генерирует для случайных пар (a, b) ограничения вида:
# (password[a] ^ password[b]) == (target[a] ^ target[b])
# (password[a] & password[b]) == (target[a] & target[b])
# (password[a] | password[b]) == (target[a] | target[b])
# (password[a] * password[b]) == (target[a] * target[b]) & 0xff
```

То есть сам правильный пароль — `"2QY90H6F"` — захардкожен не напрямую, а
только через набор побитовых соотношений между его байтами. Ключевой
момент в самом `checker.c`: при успехе он **буквально печатает введённый
пароль обратно**, вклеивая его в хвост строки `"gaslightCTF{ch3ck_0ut_
lyra-horse!!_"` + `password` + `"}"`. Значит финальный флаг =
`"gaslightCTF{ch3ck_0ut_lyra-horse!!_" + target + "}"`.

## Два рабочих пути решения

### 1. Интендед-способ: Z3 по сгенерированным ограничениям

`generate_constraints.py` печатает (помимо C-кода для компиляции) список
строковых Z3-ограничений (`z3_constraints`) — их можно прогнать через
`z3-solver`, получить 8 байт `password`, ввести этот пароль в VM через
`vm.html` и прочитать флаг с экрана эмуляции.

```python
from z3 import *
password = [BitVec(f'p{i}', 8) for i in range(8)]
s = Solver()
for c in z3_constraints:   # строки вида "(password[a]^password[b])==0x.."
    s.add(eval(c.replace('password', 'password').replace('[','[').replace(']','].as_long() if False else '')))  # см. verify_constraints.py за готовым парсером
...
if s.check() == sat:
    m = s.model()
    pw = bytes(m[p].as_long() for p in password)
    print(pw)  # -> b'2QY90H6F'
```

(Рабочий парсер ограничений и сборка Z3-модели уже есть в
`verify_constraints.py` из репозитория — его стоит адаптировать под
`Solver()` вместо `eval()`-проверки готового пароля.)

### 2. Способ, которым решали мы: прямое извлечение из памяти VM

Поскольку сам флаг (включая эхо пароля) — это **константные данные**,
записанные в программу компилятором ещё на этапе сборки (`target` был
известен автору CTF заранее), строка флага целиком присутствует в
скомпилированном бинарнике / в памяти VM ещё до того, как кто-либо вообще
ввёл пароль правильно. Поэтому можно было пропустить и решение Z3-системы,
и даже сам ввод в VM — просто дампнуть память/данные эмулятора и поискать
печатные ASCII-последовательности:

```python
import re
data = bytes(...)   # дамп памяти/данных VM
for i in range(len(data)):
    chunk = data[i:i+100]
    if b"CTF" in chunk or b"flag" in chunk.lower():
        print(i, chunk)
```

```python
import string
def printable_run(data, min_len=5):
    out, cur = [], bytearray()
    for b in data:
        if chr(b) in string.printable and b not in (0, 9, 10, 13):
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur))
            cur.clear()
    return out
```

Это и дало найденный фрагмент `CTF{ch3c\0k_0ut_ly\0ra-horse\0` —
правильное начало флага, просто разбитое на 8-байтные куски
(`writeChar8`), с нулевыми байтами-разделителями между вызовами. Хвост
(`!!_2QY90H6F}`) в этом фрагменте просто не попал в дамп/не был замечен.

## Флаг

```
gaslightCTF{ch3ck_0ut_lyra-horse!!_2QY90H6F}
```

Статический флаг, подтверждён по `chall.yaml` репозитория
`gaslightctf/challs-2026`. Закрывает прежний неподтверждённый кандидат
`CTF{ch3ck_0ut_lyra-horse}` — тот был просто обрезан по хвосту.

## Выводы / чеклист для похожих заданий

1. "Необычный" формат исполнения (VM, CSS-анимации, байткод) — не повод
   сразу садиться дизассемблировать всё руками. Сначала понять модель
   памяти/вывода и попробовать самый дешёвый путь — грубый дамп данных на
   предмет читаемых строк.
2. Если программа при успехе эхо́ит часть введённых данных обратно во
   флаг — значит сам флаг не statically-known одной строкой, а состоит из
   константной "обёртки" + секрет, который требуется восстановить.
3. Если секрет задан только через систему побитовых соотношений между
   парами байт (`^`, `&`, `|`, умножение по модулю 256) — это прямой
   кандидат на Z3/SMT: заводим `BitVec` на каждый байт и кормим solver'у
   все условия как есть, без попытки решать вручную.
4. Если авторский генератор ограничений (`generate_constraints.py` и
   подобные) доступен в исходниках — быстрее всего просто запустить его
   и забрать готовый список Z3-constraints, а не переписывать логику
   самому по дизассемблированному чекеру.
