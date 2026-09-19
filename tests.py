"""
tests.py — простые проверки шифров.

Запуск:
    python tests.py

Проверяются все семь шифров программы: Цезарь, Атбаш, ROT13, Виженер,
Плейфер, Хилл и XOR, а также частотный анализ и обработка ошибок.

Если все проверки пройдены, в конце появится надпись
«Все проверки пройдены!». Это удобно показать на защите проекта.
"""

import ciphers

FAILED = 0  # счётчик непройденных проверок


def check(name, actual, expected):
    """Сравнивает результат actual с ожидаемым expected."""
    global FAILED
    if actual == expected:
        print(f"  ok   {name}")
    else:
        FAILED += 1
        print(f"  ОШИБКА {name}: получили {actual!r}, а ждали {expected!r}")


def check_error(name, function, expected_error):
    """Проверяет, что функция поднимает нужную ошибку."""
    global FAILED
    try:
        function()
    except expected_error:
        print(f"  ok   {name}")
    except Exception as error:
        FAILED += 1
        print(f"  ОШИБКА {name}: поднята другая ошибка {error!r}")
    else:
        FAILED += 1
        print(f"  ОШИБКА {name}: ошибка не поднята вовсе")


def check_round_trip(name, text, key):
    """Проверяет шифр «по кругу»: зашифровали — расшифровали — сравнили."""
    encrypted = ciphers.hill(text, key)
    check(name, ciphers.hill(encrypted, key, decrypt=True), text)


def main():
    print("Проверяем шифры...")

    # --- Шифр Цезаря ---
    check("Цезарь, русский, сдвиг 3", ciphers.caesar("ПРИВЕТ", 3), "ТУЛЕЗХ")
    check("Цезарь, английский, сдвиг 3", ciphers.caesar("HELLO", 3), "KHOOR")
    check(
        "Цезарь, возврат назад",
        ciphers.caesar(ciphers.caesar("Привет, мир!", 7), -7),
        "Привет, мир!",
    )
    check("Цезарь, регистр букв", ciphers.caesar("Привет", 3), "Тулезх")

    # --- Шифр Атбаш ---
    check("Атбаш, русский", ciphers.atbash("ПРИВЕТ"), "ПОЦЭЪМ")
    check(
        "Атбаш, двойное применение",
        ciphers.atbash(ciphers.atbash("Hello!")),
        "Hello!",
    )

    # --- Шифр ROT13 ---
    check("ROT13, английский", ciphers.rot13("HELLO"), "URYYB")
    check(
        "ROT13, двойное применение",
        ciphers.rot13(ciphers.rot13("HELLO")),
        "HELLO",
    )
    check("ROT13, русский", ciphers.rot13("ПРИВЕТ"), "ЬЭХОСЯ")
    check(
        "ROT13, расшифровка русского",
        ciphers.rot13("ЬЭХОСЯ", decrypt=True),
        "ПРИВЕТ",
    )
    check(
        "ROT13, расшифровка английского",
        ciphers.rot13("URYYB", decrypt=True),
        "HELLO",
    )
    check(
        "ROT13, туда и обратно (русский)",
        ciphers.rot13(ciphers.rot13("Привет, мир!"), decrypt=True),
        "Привет, мир!",
    )

    # --- Шифр Виженера ---
    check("Виженер, русский", ciphers.vigenere("ПРИВЕТ", "КЛЮЧ"), "ЪЬЖЩПЮ")
    check(
        "Виженер, расшифровка",
        ciphers.vigenere("ЪЬЖЩПЮ", "КЛЮЧ", decrypt=True),
        "ПРИВЕТ",
    )
    check("Виженер, английский", ciphers.vigenere("HELLO", "KEY"), "RIJVS")

    # --- Шифр XOR ---
    encrypted = ciphers.xor_cipher("Привет, мир!", "sun")
    check(
        "XOR, расшифровка",
        ciphers.xor_cipher(encrypted, "sun", decrypt=True),
        "Привет, мир!",
    )

    # --- Шифр Плейфера ---
    check(
        "Плейфер, английский (учебный пример)",
        ciphers.playfair("instruments", "monarchy"),
        "GATLMZCLRQXA",
    )
    check(
        "Плейфер, расшифровка",
        ciphers.playfair("GATLMZCLRQXA", "monarchy", decrypt=True),
        "INSTRUMENTSX",
    )
    check(
        "Плейфер, русский",
        ciphers.playfair("Привет, мир!", "ЛЕТО"),
        "ИЦРИТО, НЙСЦ!",
    )
    check(
        "Плейфер, таблица из ключа",
        ciphers.playfair_table("ЛЕТО", ciphers.RU_ALPHABET),
        ["ЛЕТОАБ", "ВГДЁЖЗ", "ИЙКМНП", "РСУФХЦ", "ЧШЩЪЫЬ", "ЭЮЯ123"],
    )
    check(
        "Плейфер, таблица английская",
        ciphers.playfair_table("MONARCHY", ciphers.EN_ALPHABET),
        ["MONAR", "CHYBD", "EFGIK", "LPQST", "UVWXZ"],
    )

    # --- Шифр Хилла ---
    check("Хилл, шифрование", ciphers.hill("ПРИВЕТ", "АБВГ"), "РРВЧТБ")
    check(
        "Хилл, расшифровка",
        ciphers.hill("РРВЧТБ", "АБВГ", decrypt=True),
        "ПРИВЕТ",
    )
    check_round_trip("Хилл, кольцо (ГДЕБ)", "ПРИВЕТ", "ГДЕБ")
    check(
        "Хилл, матрица ключа",
        ciphers.parse_hill_key("АБВГ"),
        [[0, 1], [2, 3]],
    )
    check(
        "Хилл, определитель",
        ciphers.hill_determinant([[0, 1], [2, 3]], 33),
        31,
    )
    check(
        "Хилл, обратная матрица",
        ciphers.hill_inverse([[0, 1], [2, 3]], 33),
        [[15, 17], [1, 0]],
    )

    # --- Частотный анализ (взлом Цезаря без ключа) ---
    russian_text = (
        "ЭТО УЧЕБНЫЙ ПРОЕКТ ПО ПРОГРАММИРОВАНИЮ ОН ПОКАЗЫВАЕТ КАК "
        "РАБОТАЮТ КЛАССИЧЕСКИЕ ШИФРЫ И ПОЧЕМУ НУЖНА КРИПТОГРАФИЯ"
    )
    check(
        "Взлом Цезаря, русский текст",
        ciphers.break_caesar(ciphers.caesar(russian_text, 7)),
        (7, russian_text),
    )
    english_text = (
        "HELLO WORLD THIS IS A SECRET MESSAGE ABOUT CRYPTOGRAPHY "
        "AND IT IS QUITE LONG SO THE FREQUENCY ANALYSIS WORKS"
    )
    check(
        "Взлом Цезаря, английский текст",
        ciphers.break_caesar(ciphers.caesar(english_text, 4)),
        (4, english_text),
    )
    check(
        "Частоты букв",
        ciphers.letter_frequency("Привет, мир!"),
        {"П": 1, "Р": 2, "И": 2, "В": 1, "Е": 1, "Т": 1, "М": 1},
    )

    print("Проверяем обработку ошибок ключа...")
    check_error(
        "Виженер без ключа",
        lambda: ciphers.vigenere("ТЕКСТ", ""),
        ValueError,
    )
    check_error(
        "XOR без ключа",
        lambda: ciphers.xor_cipher("ТЕКСТ", ""),
        ValueError,
    )
    check_error(
        "Цезарь с ключом-буквой",
        lambda: ciphers.parse_shift("привет"),
        ValueError,
    )
    check_error(
        "Плейфер без ключа",
        lambda: ciphers.playfair("ТЕКСТ", ""),
        ValueError,
    )
    check_error(
        "Хилл, ключ из 3 букв",
        lambda: ciphers.hill("ТЕКСТ", "АБВ"),
        ValueError,
    )
    check_error(
        "Хилл, непригодный ключ",
        lambda: ciphers.hill("ТЕКСТ", "АААА"),
        ValueError,
    )
    check_error(
        "Взлом текста без букв",
        lambda: ciphers.break_caesar("12345"),
        ValueError,
    )

    print()
    if FAILED == 0:
        print("Все проверки пройдены! Можно показывать проект учителю.")
    else:
        print(f"Проверок с ошибками: {FAILED}.")


if __name__ == "__main__":
    main()