"""
ciphers.py — логика шифрования.

Здесь живут все шифры программы:

    * Шифр Цезаря      — сдвиг букв на N позиций;
    * Шифр Атбаш       — зеркальный алфавит;
    * Шифр ROT13       — частный случай Цезаря (сдвиг на 13);
    * Шифр Виженера    — ключевое слово задаёт сдвиг каждой буквы;
    * Шифр Плейфера    — пары букв по таблице 5x5 или 6x6;
    * Шифр Хилла       — пары букв и матрица 2x2;
    * Шифр XOR         — «сложение» байтов с ключом;
    * взлом Цезаря     — подбор сдвига методом частотного анализа.

Файл ничего не знает про интерфейс (tkinter), поэтому логику легко
проверять и переиспользовать в других программах.

Кроме шифра Хилла (он работает только с русским текстом), все шифры
поддерживают русский и английский алфавиты. Символы, которые не
являются буквами (пробелы, цифры, знаки препинания), проходят через
шифрование без изменений.
"""

import math


# ----------------------------------------------------------------------
# Алфавиты
# ----------------------------------------------------------------------

# Русский алфавит: 33 буквы. Буква «Ё» стоит на своём законном месте —
# сразу после «Е» (как в словарях и справочниках).
RU_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

# Английский алфавит: 26 букв.
EN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Кортеж алфавитов — по нему удобно перебирать в цикле.
ALPHABETS = (RU_ALPHABET, EN_ALPHABET)

# Служебная буква-«заполнитель». Шифры Плейфера и Хилла работают
# с парами букв, поэтому нечётную последнюю пару нужно чем-то дополнить.
PLAYFAIR_RU_FILLER = "Х"
PLAYFAIR_EN_FILLER = "X"


# ----------------------------------------------------------------------
# Вспомогательные функции
# ----------------------------------------------------------------------

def get_alphabet(char):
    """Возвращает алфавит, которому принадлежит буква char.

    Если char — русская или английская буква, возвращается строка
    соответствующего алфавита в верхнем регистре. Иначе — None.
    """
    upper = char.upper()
    for alphabet in ALPHABETS:
        if upper in alphabet:
            return alphabet
    return None


def shift_letter(char, shift):
    """Сдвигает одну букву на shift позиций внутри её алфавита.

    Регистр (заглавная или строчная) сохраняется. shift может быть
    отрицательным — тогда буква сдвигается в начало алфавита.
    """
    alphabet = get_alphabet(char)
    if alphabet is None:
        return char  # это не буква — оставляем символ без изменений

    index = alphabet.index(char.upper())
    new_index = (index + shift) % len(alphabet)
    new_char = alphabet[new_index]
    # Возвращаем букву в том же регистре, какой был у исходной.
    return new_char if char.isupper() else new_char.lower()


def parse_shift(key):
    """Превращает текст ключа в число (сдвиг) для шифра Цезаря.

    Если число ввести нельзя, поднимается ValueError с понятным
    объяснением — это сообщение потом показывается в окне программы.
    """
    key = key.strip()
    if not key:
        raise ValueError(
            "Для шифра Цезаря нужно число — величина сдвига (например, 3)."
        )
    try:
        return int(key)
    except ValueError:
        raise ValueError(
            "Сдвиг должен быть целым числом, например 3 или -5. "
            "Буквы в этом поле не подходят."
        ) from None


# ----------------------------------------------------------------------
# Шифры
# ----------------------------------------------------------------------

def caesar(text, shift):
    """Шифр Цезаря: каждая буква сдвигается на shift шагов по алфавиту.

    Пример: при сдвиге 3 буква А становится Г, Б становится Д, и так
    далее. Расшифровка — это шифрование с отрицательным сдвигом:
    caesar(text, -shift).

    shift должен быть целым числом.
    """
    if not isinstance(shift, int):
        raise ValueError("Сдвиг должен быть целым числом.")

    result = []
    for char in text:
        result.append(shift_letter(char, shift))
    return "".join(result)


def atbash(text):
    """Шифр Атбаш: буквы заменяются на симметричные в алфавите.

    Первая буква алфавита меняется на последнюю, вторая — на
    предпоследнюю, и так далее. Для русского алфавита:
    А <-> Я, Б <-> Ю, В <-> Э.

    Шифрование и расшифровка — одно и то же действие.
    """
    result = []
    for char in text:
        alphabet = get_alphabet(char)
        if alphabet is None:
            result.append(char)
            continue
        index = alphabet.index(char.upper())
        mirrored = alphabet[len(alphabet) - 1 - index]
        result.append(mirrored if char.isupper() else mirrored.lower())
    return "".join(result)


def rot13(text, decrypt=False):
    """Шифр ROT13: частный случай Цезаря со сдвигом на 13 позиций.

    Для английского алфавита (26 букв) сдвиг 13 — «самообратный»:
    13 + 13 = 26, то есть полный оборот, поэтому зашифровать и
    расшифровать — одно и то же действие.

    Для русского алфавита это не так: в нём 33 буквы, и 13 + 13 = 26
    не даёт полного оборота. Поэтому при расшифровке русского текста
    сдвиг делается в обратную сторону — иначе текст не восстановится.
    """
    return caesar(text, -13 if decrypt else 13)


def vigenere(text, key, decrypt=False):
    """Шифр Виженера: текст шифруется ключевым словом.

    Каждая буква текста сдвигается на столько позиций, какая буква ключа
    стоит на её месте. Ключ при этом повторяется по кругу.

    Пример: текст «ПРИВЕТ», ключ «КЛЮЧ»:
        П + К -> Ъ,  Р + Л -> Ь,  И + Ю -> Ж,  В + Ч -> Щ ...

    Если decrypt=True, буквы ключа «вычитаются», и текст расшифровывается.
    """
    # Отбираем из ключа только буквы и приводим их к верхнему регистру.
    key_letters = [ch.upper() for ch in key if get_alphabet(ch) is not None]
    if not key_letters:
        raise ValueError(
            "Для шифра Виженера нужно ключевое слово хотя бы из одной "
            "буквы (например, КЛЮЧ)."
        )

    result = []
    key_pos = 0  # номер буквы ключа: растёт только на буквах текста
    for char in text:
        alphabet = get_alphabet(char)
        if alphabet is None:
            result.append(char)
            continue

        key_char = key_letters[key_pos % len(key_letters)]
        # Позиция буквы ключа в её алфавите — это и есть сдвиг.
        shift = get_alphabet(key_char).index(key_char)
        if decrypt:
            shift = -shift

        result.append(shift_letter(char, shift))
        key_pos += 1

    return "".join(result)


def _detect_alphabet(text):
    """Определяет, на каком алфавите написан текст.

    Считает, каких букв больше — русских или английских, — и возвращает
    нужный алфавит. Если букв в тексте нет вовсе, возвращает None.
    """
    ru_count = sum(1 for char in text if char.upper() in RU_ALPHABET)
    en_count = sum(1 for char in text if char.upper() in EN_ALPHABET)
    if ru_count == 0 and en_count == 0:
        return None
    return RU_ALPHABET if ru_count >= en_count else EN_ALPHABET


def playfair_table(key, alphabet):
    """Строит таблицу для шифра Плейфера из ключевого слова.

    Сначала в таблицу попадают буквы ключа (без повторов), а затем —
    остальные буквы алфавита. Размер таблицы зависит от алфавита:

        * английский — 5x5 (буквы J и I объединяются, как принято
          в классическом шифре Плейфера);
        * русский — 6x6 (33 буквы плюс три служебные клетки «123»).

    Возвращает список строк таблицы.
    """
    if alphabet == EN_ALPHABET:
        size = 5
        source = EN_ALPHABET.replace("J", "")   # J объединяем с I
    else:
        size = 6
        source = RU_ALPHABET + "123"            # добираем до 36 клеток

    letters = ""
    for char in key.upper():
        if char == "J" and alphabet == EN_ALPHABET:
            char = "I"
        if char in source and char not in letters:
            letters += char
    for char in source:
        if char not in letters:
            letters += char

    table = []
    for row in range(size):
        start = row * size
        table.append(letters[start:start + size])
    return table


def _playfair_position(table, char):
    """Ищет букву в таблице. Возвращает пару (строка, столбец)."""
    for row_number, row in enumerate(table):
        if char in row:
            return row_number, row.index(char)
    return None


def _playfair_pair(table, first, second, decrypt):
    """Шифрует одну пару букв по правилам Плейфера.

    Три правила шифра (при расшифровке сдвиг идёт в другую сторону):

        1. буквы в одной строке — берём соседние справа;
        2. буквы в одном столбце — берём соседние снизу;
        3. иначе — «прямоугольник»: каждая буква берёт столбец другой.
    """
    row1, col1 = _playfair_position(table, first)
    row2, col2 = _playfair_position(table, second)
    size = len(table)
    shift = -1 if decrypt else 1

    if row1 == row2:
        return (
            table[row1][(col1 + shift) % size],
            table[row2][(col2 + shift) % size],
        )
    if col1 == col2:
        return (
            table[(row1 + shift) % size][col1],
            table[(row2 + shift) % size][col2],
        )
    return (table[row1][col2], table[row2][col1])


def _playfair_prepare(letters, filler, decrypt):
    """Готовит буквы к шифрованию парами.

    При шифровании: если рядом стоят две одинаковые буквы, между ними
    вставляется заполнитель. При расшифровке так делать нельзя — там
    пары уже заданы, и их нужно брать как есть.

    В обоих случаях нечётное число букв дополняется заполнителем.
    """
    prepared = list(letters)
    if not decrypt:
        prepared = []
        index = 0
        while index < len(letters):
            prepared.append(letters[index])
            if index + 1 < len(letters):
                if letters[index] == letters[index + 1]:
                    prepared.append(filler)   # одинаковые буквы «разводим»
                else:
                    prepared.append(letters[index + 1])
                    index += 1
            index += 1

    if len(prepared) % 2:
        prepared.append(filler)           # дополняем последнюю пару
    return prepared


def _playfair_encrypt_letters(letters, table, filler, decrypt):
    """Шифрует порцию букв (обычно одно слово) парами по таблице."""
    prepared = _playfair_prepare(letters, filler, decrypt)
    parts = []
    for position in range(0, len(prepared), 2):
        first, second = _playfair_pair(
            table, prepared[position], prepared[position + 1], decrypt
        )
        parts.append(first + second)
    return "".join(parts)


def playfair(text, key, decrypt=False):
    """Шифр Плейфера: буквы шифруются парами по квадратной таблице.

    Это первый «серьёзный» шифр программы: он превращает сразу по две
    буквы, поэтому обычный подсчёт частот букв (как для Цезаря) уже
    не помогает взломщику. Именно Плейфером пользовались в Первую
    мировую войну.

    Как это работает по шагам:

        1. из ключевого слова строится таблица (5x5 или 6x6);
        2. текст разбивается на пары букв;
        3. каждая пара заменяется по правилам строки, столбца или
           «прямоугольника» (см. _playfair_pair).

    Шифруются только буквы: пробелы и знаки препинания остаются
    на своих местах. Результат выводится заглавными буквами, а из-за
    вставки заполнителя при расшифровке в конце может появиться лишняя
    буква — так устроен классический Плейфер.
    """
    if not key.strip():
        raise ValueError(
            "Для шифра Плейфера нужно ключевое слово (например, ЛЕТО)."
        )

    alphabet = _detect_alphabet(text)
    if alphabet is None:
        raise ValueError(
            "В тексте нет букв — шифру Плейфера нечего шифровать."
        )

    table = playfair_table(key, alphabet)
    if alphabet == RU_ALPHABET:
        filler = PLAYFAIR_RU_FILLER
    else:
        filler = PLAYFAIR_EN_FILLER

    result = []
    letters = []       # буквы текущего слова

    for char in text:
        if get_alphabet(char) is not None:
            letter = char.upper()
            if alphabet == EN_ALPHABET and letter == "J":
                letter = "I"     # в английской таблице нет отдельной J
            letters.append(letter)
            continue
        # Пробел или знак препинания: сначала шифруем накопленное слово.
        if letters:
            result.append(
                _playfair_encrypt_letters(letters, table, filler, decrypt)
            )
            letters = []
        result.append(char)

    if letters:
        result.append(
            _playfair_encrypt_letters(letters, table, filler, decrypt)
        )

    return "".join(result)


def _xor_bytes(data, key):
    """Применяет операцию XOR к байтам data, повторяя ключ по кругу."""
    key_bytes = key.encode("utf-8")
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key_bytes[i % len(key_bytes)])
    return bytes(result)


def xor_cipher(text, key, decrypt=False):
    """Современный шифр XOR: байты текста «складываются» с байтами ключа.

    XOR — операция над двоичными разрядами: если биты одинаковые,
    результат 0, если разные — 1. Применив её два раза с одним ключом,
    мы получаем исходные данные, поэтому шифрование и расшифровка —
    одно и то же действие.

    Чтобы на экране не появлялись «мусорные» символы, результат
    шифрования записывается в виде шестнадцатеричных цифр (так удобно
    показывать байты).
    """
    if not key:
        raise ValueError("Для шифра XOR нужно ключевое слово (например, sun).")

    if decrypt:
        # Пользователь мог вставить пробелы между байтами — убираем их.
        clean_hex = "".join(text.split())
        try:
            data = bytes.fromhex(clean_hex)
        except ValueError:
            raise ValueError(
                "Не получается прочитать зашифрованный текст: это не "
                "шестнадцатеричный код. Нажмите «Зашифровать» заново и "
                "скопируйте результат целиком."
            ) from None
        return _xor_bytes(data, key).decode("utf-8", errors="replace")

    data = text.encode("utf-8")
    return _xor_bytes(data, key).hex()


# ----------------------------------------------------------------------
# Частотный анализ: взлом шифра Цезаря без ключа
# ----------------------------------------------------------------------

# Как часто буквы встречаются в обычных текстах (в процентах).
# Это главное «оружие» взломщика: в русском языке чаще всего
# встречаются О, Е и А, а буквы Ф, Э и Ъ — редкость.
RU_LETTER_FREQUENCY = {
    "О": 10.97, "Е": 8.45, "А": 8.01, "И": 7.35, "Н": 6.70,
    "Т": 6.26, "С": 5.47, "Р": 4.73, "В": 4.54, "Л": 4.40,
    "К": 3.49, "М": 3.21, "Д": 2.98, "П": 2.81, "У": 2.62,
    "Я": 2.01, "Ы": 1.90, "Ь": 1.74, "Г": 1.70, "З": 1.65,
    "Б": 1.59, "Ч": 1.44, "Й": 1.21, "Х": 0.97, "Ж": 0.94,
    "Ш": 0.73, "Ю": 0.64, "Ц": 0.48, "Щ": 0.36, "Э": 0.32,
    "Ф": 0.26, "Ъ": 0.04, "Ё": 0.04,
}

EN_LETTER_FREQUENCY = {
    "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97,
    "N": 6.75, "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25,
    "L": 4.03, "C": 2.78, "U": 2.76, "M": 2.41, "W": 2.36,
    "F": 2.23, "G": 2.02, "Y": 1.97, "P": 1.93, "B": 1.29,
    "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15, "Q": 0.10,
    "Z": 0.07,
}


def letter_frequency(text):
    """Считает, сколько раз встретилась каждая буква текста.

    Возвращает словарь вида {"О": 5, "Е": 3, ...}. Регистр не важен,
    символы, которые не являются буквами, в подсчёт не попадают.
    """
    counts = {}
    for char in text.upper():
        if get_alphabet(char) is not None:
            counts[char] = counts.get(char, 0) + 1
    return counts


def break_caesar(text):
    """Взламывает шифр Цезаря без ключа — методом частотного анализа.

    Идея: пробуем все возможные сдвиги и для каждого варианта считаем
    «похожесть на настоящий текст». Похожесть — это сумма частот букв:
    если после сдвига часто встречаются буквы О, Е, А (а не Щ, Ъ, Э),
    значит сдвиг, скорее всего, угадан правильно.

    Возвращает кортеж (сдвиг, расшифрованный текст).
    """
    alphabet = _detect_alphabet(text)
    if alphabet is None:
        raise ValueError(
            "В тексте нет букв — подбирать сдвиг не из чего."
        )

    if alphabet == RU_ALPHABET:
        frequency = RU_LETTER_FREQUENCY
    else:
        frequency = EN_LETTER_FREQUENCY

    best_shift = 0
    best_test = text
    best_score = -1.0

    for shift in range(len(alphabet)):
        # Если текст зашифровали сдвигом shift, то для расшифровки
        # его надо сдвинуть на -shift.
        test = caesar(text, -shift)
        score = 0.0
        for char in test:
            score += frequency.get(char.upper(), 0.0)
        if score > best_score:
            best_score = score
            best_shift = shift
            best_test = test

    return best_shift, best_test


# ----------------------------------------------------------------------
# Шифр Хилла: буквы шифруются парами с помощью матрицы 2x2
# ----------------------------------------------------------------------

def parse_hill_key(key):
    """Превращает ключ из четырёх русских букв в матрицу 2x2.

    Буквы превращаются в числа по их месту в алфавите (А=0, Б=1, ...).
    Например, ключ «АБВГ» даёт матрицу

        [[0, 1],
         [2, 3]]

    Если букв не четыре или среди них есть английские, поднимается
    ValueError с понятным объяснением.
    """
    key = key.upper().strip()
    if len(key) != 4:
        raise ValueError(
            "Для шифра Хилла нужен ключ ровно из 4 русских букв, "
            "например АБВГ."
        )

    numbers = []
    for char in key:
        if char not in RU_ALPHABET:
            raise ValueError(
                f"В ключе шифра Хилла только русские буквы, а «{char}» "
                "не подходит. Попробуйте ключ АБВГ."
            )
        numbers.append(RU_ALPHABET.index(char))
    return [numbers[0:2], numbers[2:4]]


def hill_determinant(matrix, modulus):
    """Считает определитель матрицы 2x2 по модулю.

    Определитель — это «особое число» матрицы (ad - bc). Если он не
    взаимно прост с числом букв алфавита, расшифровать текст нельзя.
    """
    return (
        matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
    ) % modulus


def hill_inverse(matrix, modulus):
    """Строит обратную матрицу 2x2 — она нужна для расшифровки.

    Обратная матрица «отменяет» умножение на ключ. Для 2x2 она
    получается по формуле adj(A) / det(A), где деление заменяется
    умножением на обратное число по модулю.
    """
    determinant = hill_determinant(matrix, modulus)
    if math.gcd(determinant, modulus) != 1:
        raise ValueError(
            f"Ключ не подходит: определитель матрицы равен "
            f"{determinant}, а он должен быть взаимно прост с числом "
            f"букв алфавита ({modulus}). Попробуйте ключ АБВГ или ГДЕБ."
        )

    reverse = pow(determinant, -1, modulus)   # обратное число по модулю
    return [
        [(matrix[1][1] * reverse) % modulus,
         (-matrix[0][1] * reverse) % modulus],
        [(-matrix[1][0] * reverse) % modulus,
         (matrix[0][0] * reverse) % modulus],
    ]


def _hill_vector(matrix, vector, modulus):
    """Умножает матрицу на столбик из двух чисел и берёт остаток."""
    return [
        (matrix[row][0] * vector[0] + matrix[row][1] * vector[1])
        % modulus
        for row in range(2)
    ]


def hill(text, key, decrypt=False):
    """Шифр Хилла: буквы шифруются парами по 2 с помощью матрицы.

    Это самый «математический» шифр программы. Работает так:

        1. из четырёх букв ключа строится матрица 2x2 (А=0, Б=1, ...);
        2. текст разбивается на пары букв, каждая пара превращается
           в столбик из двух чисел;
        3. столбик умножается на матрицу, и числа снова превращаются
           в буквы.

    Для расшифровки используется обратная матрица — та же математика,
    но «в другую сторону».

    Важно: шифр Хилла работает только с русскими буквами, поэтому
    программа предупредит, если текст английский.
    """
    if not key.strip():
        raise ValueError(
            "Для шифра Хилла нужен ключ ровно из 4 русских букв."
        )

    if any(char.upper() in EN_ALPHABET for char in text):
        raise ValueError(
            "Шифр Хилла в этой программе работает только с русскими "
            "буквами. Введите текст по-русски."
        )

    if not any(get_alphabet(char) is not None for char in text):
        raise ValueError(
            "В тексте нет букв — шифру Хилла нечего шифровать."
        )

    modulus = len(RU_ALPHABET)
    matrix = parse_hill_key(key)
    # Обратную матрицу считаем всегда: для расшифровки она нужна,
    # а при шифровании она заодно проверяет, что ключ вообще годится.
    inverse = hill_inverse(matrix, modulus)
    used_matrix = inverse if decrypt else matrix

    result = []
    letters = []       # буквы текущего слова

    for char in text:
        if get_alphabet(char) is not None:
            letters.append(char.upper())
            continue
        # Пробел или знак препинания: сначала шифруем накопленное слово.
        if letters:
            result.append(_hill_word(letters, used_matrix, decrypt))
            letters = []
        result.append(char)

    if letters:
        result.append(_hill_word(letters, used_matrix, decrypt))

    return "".join(result)


def _hill_word(letters, matrix, decrypt):
    """Шифрует одно слово (без пробелов) парами букв.

    При шифровании нечётное слово дополняется заполнителем «Х»,
    а две одинаковые буквы подряд «разводятся» им же. При расшифровке
    буквы берутся парами как есть: иначе пары сдвинулись бы
    и расшифровка сломалась.
    """
    prepared = list(letters)
    if not decrypt:
        prepared = []
        index = 0
        while index < len(letters):
            prepared.append(letters[index])
            if index + 1 < len(letters):
                if letters[index] == letters[index + 1]:
                    prepared.append("Х")
                else:
                    prepared.append(letters[index + 1])
                    index += 1
            index += 1

    if len(prepared) % 2:
        prepared.append("Х")

    modulus = len(RU_ALPHABET)
    parts = []
    for position in range(0, len(prepared), 2):
        vector = [
            RU_ALPHABET.index(prepared[position]),
            RU_ALPHABET.index(prepared[position + 1]),
        ]
        numbers = _hill_vector(matrix, vector, modulus)
        parts.append(
            "".join(RU_ALPHABET[number] for number in numbers)
        )
    return "".join(parts)