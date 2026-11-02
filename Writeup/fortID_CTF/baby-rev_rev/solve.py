import hashlib
import itertools
import os
import re

TARGET = "33696-7383-3824-4-9465664238-36-32347-878267-8766-348-55487-74-0133-24566"
HASH = "3576c495f89236515fbbfbfb519dceb9899122e92460d418d2ce37a1ff357e0c"
PREFIX, SUFFIX = "FortID{", "}"
TOTAL_LEN = 81

KEYPAD = {
    "2": "abc", "3": "def", "4": "ghi", "5": "jkl",
    "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz",
}
LETTER2DIGIT = {c: d for d, letters in KEYPAD.items() for c in letters}


def t9(word: str) -> str:
    """Та же логика, что в t9text.get_touchtone: буква -> кнопка, цифра -> цифра."""
    return "".join(LETTER2DIGIT.get(c, c) for c in word)


def load_words():
    """Возвращает список слов, самые частотные первыми."""
    words = []
    try:
        from wordfreq import top_n_list
        words += top_n_list("en", 300000)
    except ImportError:
        pass
    for path in ("/usr/share/dict/words", "/usr/share/dict/american-english"):
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="ignore") as f:
                words += [w.strip().lower() for w in f]
    seen, out = set(), []
    for w in words:
        if re.fullmatch(r"[a-z]+", w) and w not in seen:
            seen.add(w)
            out.append(w)
    if not out:
        raise SystemExit("Нет словаря: установи `pip install wordfreq`.")
    return out


def main():
    # Ключевой момент: целевая строка развёрнута -> разворачиваем обратно
    tokens = TARGET[::-1].split("-")
    print("T9-токены:", tokens)

    # Один проход по словарю: T9-код -> список слов
    by_code = {}
    for w in load_words():
        by_code.setdefault(t9(w), []).append(w)

    # Кандидаты для каждого токена: слова + «чистые цифры» (слово из цифр = сам токен)
    cands = []
    for tok in tokens:
        c = by_code.get(tok, [])[:200]  # самые частотные
        c = c + [tok]
        cands.append(c)
        print(f"  {tok:>12}: {len(c)} кандидатов, например {c[:6]}")

    # Перебор с проверкой sha256
    total = 1
    for c in cands:
        total *= len(c)
    print(f"Комбинаций: {total:,}")

    for combo in itertools.product(*cands):
        flag = PREFIX + "_".join(combo) + SUFFIX
        if len(flag) != TOTAL_LEN:
            continue
        if hashlib.sha256(flag.encode()).hexdigest() == HASH:
            print("\nFLAG:", flag)
            return
    print("Не нашли: расширь словарь или число кандидатов на токен.")


if __name__ == "__main__":
    main()