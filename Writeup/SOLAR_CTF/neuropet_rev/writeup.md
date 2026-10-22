# NeuroPet — SOLAR CTF writeup

Oct 17, 2026 · @Demian

## TL;DR

**Задача:** NeuroPet («нейротамагочи в каждый дом») · **Категория:** Android reverse engineering · **Формат флага:** `SOLARCTF{}`

Флаг:

```
SOLARCTF{FR1d0Mp_Sc4n_p4G3s_in_GamEEE}
```

Дан файл `neuropet.ab` (Android backup, пароль `0000`). Путь к флагу — пятислойная матрёшка:

1. `.ab` — это не шифр, а zlib-поток → достаём APK.
2. В APK основная логика спрятана: Java-слой почти пустой, всё уходит в JNI.
3. `App.onCreate` расшифровывает скрытый dex из `assets/neuro/skin.dat` (XOR с гаммой LCG) → секретная `LabActivity`, открываемая 5 быстрыми тапами по логотипу.
4. Лаборатория дёргает нативный `run("devroom")` → `query(0)`. Вся логика в `libneurocore.so`, который оказывается стековой виртуальной машиной.
5. VM исполняет байткод из `assets/neuro/brain.bin` (каждая функция зашифрована LCG-XOR). Реверсим VM, пишем эмулятор на Python, прогоняем `devroom` — он выдаёт 4 сегмента, складывающиеся во флаг.

Главная «подлянка»: нативка содержит анти-Frida / анти-debug поток, убивающий процесс при обнаружении инструментовки. Поэтому динамический анализ здесь не работает — задача решается чисто статически.

## Stage 1 — распаковка Android backup

У файла `neuropet.ab` заголовок `ANDROID BACKUP`. Формат: 4 текстовые строки, дальше — поток.

```
ANDROID BACKUP
1          ← версия
1          ← флаг сжатия (zlib)
none       ← шифрование
```

Третья строка — `none`: шифрования нет. **Пароль `0000` — редхерринг**: ничего не дешифрует, поток просто сжат zlib. Отбрасываем 4 строки заголовка и распаковываем остаток в `.tar`:

```python
import zlib
d = open('neuropet.ab','rb').read()
i = 0
for _ in range(4):
    i = d.index(b'\n', i) + 1
open('backup.tar','wb').write(zlib.decompress(d[i:]))
```

Внутри tar — стандартная раскладка adb-бэкапа одного приложения:

```
apps/com.solarlabs.neuropet/_manifest
apps/com.solarlabs.neuropet/a/base.apk      ← сам APK
apps/com.solarlabs.neuropet/f/rList        ← сериализованный ArrayList
```

Файл `f/rList` — это Java-сериализованный `ArrayList`, содержащий строку `2130837504` (= `0x7f020000`, id ресурса `btn_pill`). Это тоже отвлекающий манёвр — к флагу отношения не имеет.

Работаем дальше с `base.apk`.

## Stage 2 — триаж APK

Распаковываем АПК и декомпилируем `jadx -d out base.apk`. Интересные ассеты:

```
assets/neuro/brain.bin     NRBC... (1865 байт)   ← байткод VM
assets/neuro/weights.bin   NRWT... (262154 байт) ← балласт / отвлечение
assets/neuro/skin.dat      (5342 байта)        ← зашифрованный dex
lib/arm64-v8a/libneurocore.so
lib/x86_64/libneurocore.so                        ← нативная VM
```

В Java-коде всё обфусцировано и почти пусто. Ключевые классы:

- **`MainActivity`** — само тамагочи (кнопки feed/play/bed, прогресс-бары). Содержит анти-эмулятор / анти-root проверки (`Build.FINGERPRINT`, `/system/bin/su` и т.д.).
- **`core.Q`** — JNI-обёртка над `libneurocore`: `nInit(byte[])`, `nRun(String)`, `nQuery(int)`, `nMoodTick()`. Вся реальная логика живёт здесь, в нативке.
- **`App.onCreate`** — самое важное. Имя ассета собирается из XOR-массива, из него читается и **расшифровывается скрытый dex**, который грузится через `InMemoryDexClassLoader` и подменяет ClassLoader приложения через рефлексию.
- **`AboutActivity`** — по тапу по `brand_word` дёргает метод `hit()` из скрытого dex; при успехе запускает `LabActivity`.

Имена классов скрытого dex тоже XOR-ятся в рантайме, например:

```python
# com.solarlabs.neuropet.lab.Trig
bytes_ = [94,82,80,19,78,82,81,92,79,81,92,95,78,19,83,88,72,79,82,77,88,73,19,81,92,95,19,105,79,84,90]
print(''.join(chr(b ^ 61) for b in bytes_))
```

Анти-эмулятор/анти-root в `MainActivity` при срабатывании просто меняет поведение питомца — напрямую флаг не блокирует, но сигнализирует, что автор против динамики.

## Stage 3 — скрытый dex и секретная лаборатория

Имя ассета в `App.onCreate` — это `neuro/skin.dat` (XOR массива с 43). Дальше содержимое расшифровывается гаммой линейного конгруэнтного генератора (LCG, те же константы, что в glibc `rand`):

- seed = первые 2 байта файла (little-endian);
- на каждый байт: `state = (state*1103515245 + 12345) & 0xffffffff`, ключевой байт = `(state >> 16) & 0xff`;
- первые 4 байта результата принудительно заменяются на `dex\n` (магия dex).

```python
g = open('skin.dat','rb').read()
st = g[0] | (g[1] << 8)
out = bytearray()
for b in g[2:]:
    st = (st*1103515245 + 12345) & 0xffffffff
    out.append(((st >> 16) & 0xff) ^ b)
out[0:4] = b'dex\n'
open('skin.dex','wb').write(out)
```

В расшифрованном dex — пакет `com.solarlabs.neuropet.lab`:

- **`Trig.hit()`** — счётчик тапов: 5 нажатий за 1500 мс по логотипу → `true`.
- **`LabActivity`** — секретный экран. Через пару секунд анимации он вызывает:

```java
Io io = Wire.link;              // = core.Q, нативная VM
io.run(LabActivity.de(53, {81,80,67,71,90,90,88}));  // "devroom"
LabHold.seg = io.query(0);      // читает результат
```

Строка-аргумент `de(53, {...})` = XOR с 53 → **`devroom`**. То есть лаборатория просит нативную VM выполнить функцию `devroom` и вернуть результат. Вся соль — в `libneurocore.so`.
