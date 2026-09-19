"""
gui.py — графический интерфейс программы «Шифратор».

Интерфейс построен на стандартной библиотеке tkinter с расширением
ttk (темы, аккуратные кнопки). Дополнительные библиотеки устанавливать
не нужно. Все подписи и сообщения — на русском языке.

Окно содержит:
    * поле ввода исходного текста;
    * выбор шифра и поле для ключа;
    * кнопки «Зашифровать», «Расшифровать», «Очистить»,
      «Скопировать результат», «Сохранить в файл», «Открыть файл»;
    * кнопку «Взломать Цезаря» — она подбирает сдвиг методом
      частотного анализа, то есть показывает, как шифр взламывают
      без ключа;
    * поле с результатом (только для чтения);
    * строку состояния внизу.
"""

import base64
import struct
import tkinter as tk
import zlib
from tkinter import filedialog, messagebox, ttk

import ciphers

# Названия шифров в выпадающем списке -> внутренние имена.
CIPHERS = {
    "Шифр Цезаря (сдвиг)": "caesar",
    "Шифр Виженера (ключевое слово)": "vigenere",
    "Шифр Атбаш (зеркальный алфавит)": "atbash",
    "Шифр ROT13 (сдвиг на 13)": "rot13",
    "Шифр Плейфера (пары букв)": "playfair",
    "Шифр Хилла (матрица 2x2)": "hill",
    "Шифр XOR (современный)": "xor",
}

# Подсказки под полем ключа — для каждого шифра своя.
KEY_HINTS = {
    "caesar": "Введите число — на сколько позиций сдвигать (например, 3)",
    "vigenere": "Введите ключевое слово (например, КЛЮЧ)",
    "atbash": "Ключ не нужен — этот шифр работает сам",
    "rot13": "Ключ не нужен — сдвиг на 13 задан заранее",
    "playfair": (
        "Введите ключевое слово (например, ЛЕТО). Парный шифр: "
        "при расшифровке в конце слов может появиться буква Х"
    ),
    "hill": (
        "Введите ключ ровно из 4 русских букв (например, АБВГ). "
        "Работает только с русским текстом"
    ),
    "xor": "Введите ключ-слово (например, sun)",
}

# Цветовая палитра интерфейса.
COLORS = {
    "bg": "#1c2a4a",          # главный фон окна
    "text": "#eaf2ff",        # цвет подписей
    "hint": "#9fb6d9",        # цвет подсказок
    "title": "#ffcf4d",       # цвет заголовка
    "accent": "#4a90d9",      # акцентный синий (кнопки)
    "button": "#2a3d66",      # обычные кнопки
    "entry_bg": "#f5f7fa",    # фон полей ввода
    "entry_fg": "#1c2333",    # цвет текста в полях ввода
    "result_bg": "#0f172a",   # фон поля результата
    "result_fg": "#6fe89b",   # цвет текста результата
}


def run_cipher(cipher_name, text, key, decrypt):
    """Вызывает нужный шифр по его внутреннему имени.

    Возвращает строку-результат. При неверном ключе поднимает ValueError
    с понятным сообщением — программа покажет его во всплывающем окне.
    """
    if cipher_name == "caesar":
        shift = ciphers.parse_shift(key)
        return ciphers.caesar(text, -shift if decrypt else shift)
    if cipher_name == "vigenere":
        return ciphers.vigenere(text, key, decrypt)
    if cipher_name == "atbash":
        return ciphers.atbash(text)
    if cipher_name == "rot13":
        return ciphers.rot13(text, decrypt)
    if cipher_name == "playfair":
        return ciphers.playfair(text, key, decrypt)
    if cipher_name == "hill":
        return ciphers.hill(text, key, decrypt)
    if cipher_name == "xor":
        return ciphers.xor_cipher(text, key, decrypt)
    raise ValueError("Такого шифра нет в программе.")


def make_icon(master=None, size=32):
    """Создаёт иконку окна программно — без файла-картинки.

    Сами рисуем картинку 32x32: тёмно-синий фон и белая буква «Ш»
    (первая буква слова «Шифратор»). Картинку собираем в формате PNG —
    стандартными библиотеками zlib и struct (в Tk 9 это единственный
    встроенный растровый формат). Если что-то не получилось,
    возвращается None — программа работает с обычной иконкой.
    """
    try:
        background = (28, 42, 74)      # цвет фона
        foreground = (255, 255, 255)   # цвет буквы

        # Собираем «сырые» пиксели: каждая строка PNG начинается
        # с байта фильтра (0 — без фильтров), дальше идут RGB-тройки.
        raw = bytearray()
        for y in range(size):
            raw.append(0)
            for x in range(size):
                color = background
                # Буква «Ш»: три вертикальных полоски и верхняя черта.
                vertical = (
                    (6 <= x <= 9 or 15 <= x <= 18 or 24 <= x <= 27)
                    and 10 <= y <= 27
                )
                horizontal = 6 <= x <= 27 and 5 <= y <= 8
                if vertical or horizontal:
                    color = foreground
                raw.extend(color)

        def chunk(kind, data):
            """Собирает один блок PNG: длина, имя, данные, сумма."""
            length = struct.pack(">I", len(data))
            checksum = struct.pack(
                ">I", zlib.crc32(kind + data) & 0xFFFFFFFF
            )
            return length + kind + data + checksum

        # Заголовок PNG: размер 8-битных каналов, цветная модель RGB.
        ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
        png = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b"")
        )
        icon_data = base64.b64encode(png)
        return tk.PhotoImage(master=master, data=icon_data)
    except Exception:
        return None


class CipherApp:
    """Главное окно программы «Шифратор»."""

    def __init__(self, root):
        self.root = root
        self.root.title("Шифратор — шифрование текста (Python)")
        self.root.geometry("820x720")
        self.root.minsize(700, 620)

        self._setup_style()
        self._build_widgets()
        self._on_cipher_changed()  # подсказка про ключ для первого шифра
        self._update_status(
            "Добро пожаловать! Введите текст и нажмите «Зашифровать»."
        )

    # ------------------------------------------------------------------
    # Оформление
    # ------------------------------------------------------------------

    def _setup_style(self):
        """Настраивает единый стиль (шрифты и цвета) для всех виджетов."""
        style = ttk.Style(self.root)
        style.theme_use("clam")

        # Рамки окна и панелей.
        style.configure("App.TFrame", background=COLORS["bg"])

        # Подписи и текст.
        style.configure(
            "TLabel",
            background=COLORS["bg"],
            foreground=COLORS["text"],
            font=("Segoe UI", 11),
        )
        style.configure(
            "Title.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["title"],
            font=("Segoe UI", 18, "bold"),
        )
        style.configure(
            "Hint.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["hint"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Status.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["hint"],
            font=("Segoe UI", 10),
            relief="sunken",
            padding=(10, 5),
        )

        # Кнопки.
        style.configure(
            "TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 7),
            background=COLORS["button"],
            foreground=COLORS["text"],
        )
        style.map(
            "TButton",
            background=[("active", "#3d5a99"), ("pressed", "#26385f")],
            foreground=[("disabled", "#7d8cb0")],
        )
        style.configure(
            "Accent.TButton",
            background=COLORS["accent"],
            foreground="#ffffff",
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#5aa0e6"), ("pressed", "#3678b5")],
        )

        # Поле выбора и поле ключа.
        style.configure(
            "TCombobox",
            font=("Segoe UI", 11),
            fieldbackground=COLORS["entry_bg"],
            background=COLORS["entry_bg"],
            foreground=COLORS["entry_fg"],
            arrowcolor=COLORS["accent"],
            padding=4,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", COLORS["entry_bg"])],
        )
        style.configure(
            "TEntry",
            font=("Segoe UI", 11),
            fieldbackground=COLORS["entry_bg"],
            foreground=COLORS["entry_fg"],
            padding=4,
        )

    def _build_widgets(self):
        """Создаёт все элементы интерфейса и раскладывает их по сетке."""
        outer = ttk.Frame(self.root, style="App.TFrame", padding=18)
        outer.pack(fill="both", expand=True)

        # --- Заголовок ---
        ttk.Label(outer, text="Шифратор текста", style="Title.TLabel").pack(
            anchor="w"
        )
        ttk.Label(
            outer,
            text="Учебный проект по Python: классические шифры "
                 "и современный XOR",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(2, 10))

        ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=(0, 10))

        # --- Исходный текст ---
        ttk.Label(outer, text="Исходный текст:").pack(anchor="w")
        self.input_text = tk.Text(
            outer,
            height=6,
            wrap="word",
            font=("Consolas", 11),
            bg=COLORS["entry_bg"],
            fg=COLORS["entry_fg"],
            insertbackground=COLORS["entry_fg"],
            relief="flat",
            padx=10,
            pady=8,
        )
        self.input_text.pack(fill="x", pady=(4, 10))
        # Ctrl+Enter в поле ввода сразу шифрует текст.
        self.input_text.bind("<Control-Return>", lambda event: self._encrypt())
        # При обычном вводе обновляем счётчик символов в статус-баре.
        self.input_text.bind("<KeyRelease>", self._on_text_edited)

        # --- Выбор шифра и ключа ---
        settings = ttk.Frame(outer, style="App.TFrame", padding=(0, 4))
        settings.pack(fill="x")

        ttk.Label(settings, text="Шифр:").grid(row=0, column=0, sticky="w")
        self.cipher_box = ttk.Combobox(
            settings,
            values=list(CIPHERS.keys()),
            state="readonly",
            width=36,
        )
        self.cipher_box.current(0)
        self.cipher_box.grid(row=0, column=1, padx=8, sticky="w")
        self.cipher_box.bind("<<ComboboxSelected>>", self._on_cipher_changed)

        ttk.Label(settings, text="Ключ:").grid(row=0, column=2, sticky="w")
        self.key_entry = ttk.Entry(settings, width=24)
        self.key_entry.grid(row=0, column=3, padx=8, sticky="w")

        self.key_hint = ttk.Label(settings, text="", style="Hint.TLabel")
        self.key_hint.grid(
            row=1, column=0, columnspan=4, sticky="w", pady=(6, 0)
        )

        # --- Кнопки ---
        actions = ttk.Frame(outer, style="App.TFrame", padding=(0, 8))
        actions.pack(fill="x")

        self.encrypt_button = ttk.Button(
            actions,
            text="Зашифровать",
            style="Accent.TButton",
            command=self._encrypt,
        )
        self.encrypt_button.grid(row=0, column=0, padx=(0, 10))

        self.decrypt_button = ttk.Button(
            actions,
            text="Расшифровать",
            style="Accent.TButton",
            command=self._decrypt,
        )
        self.decrypt_button.grid(row=0, column=1)

        self.clear_button = ttk.Button(
            actions, text="Очистить", command=self._clear
        )
        self.clear_button.grid(row=1, column=0, padx=(0, 10), pady=(6, 0))

        self.copy_button = ttk.Button(
            actions,
            text="Скопировать результат",
            command=self._copy_result,
        )
        self.copy_button.grid(row=1, column=1, padx=(0, 10), pady=(6, 0))

        self.save_button = ttk.Button(
            actions,
            text="Сохранить в файл",
            command=self._save_result,
        )
        self.save_button.grid(row=1, column=2, pady=(6, 0))

        self.open_button = ttk.Button(
            actions,
            text="Открыть файл",
            command=self._open_file,
        )
        self.open_button.grid(row=2, column=0, padx=(0, 10), pady=(6, 0))

        # Эта кнопка показывает, что шифр Цезаря можно взломать
        # без ключа — по частоте букв.
        self.break_button = ttk.Button(
            actions,
            text="Взломать Цезаря (частотный анализ)",
            command=self._break_caesar,
        )
        self.break_button.grid(
            row=2, column=1, columnspan=2, sticky="w", pady=(6, 0)
        )

        # --- Результат ---
        ttk.Label(outer, text="Результат:").pack(anchor="w", pady=(10, 4))
        self.result_text = tk.Text(
            outer,
            height=6,
            wrap="word",
            font=("Consolas", 11),
            bg=COLORS["result_bg"],
            fg=COLORS["result_fg"],
            state="disabled",
            relief="flat",
            padx=10,
            pady=8,
        )
        self.result_text.pack(fill="x")

        # --- Строка состояния ---
        self.status_var = tk.StringVar()
        ttk.Label(
            outer,
            textvariable=self.status_var,
            style="Status.TLabel",
            anchor="w",
        ).pack(fill="x", side="bottom", pady=(14, 0))

    # ------------------------------------------------------------------
    # Обработчики событий
    # ------------------------------------------------------------------

    def _current_cipher(self):
        """Возвращает внутреннее имя шифра из выпадающего списка."""
        return CIPHERS[self.cipher_box.get()]

    def _on_cipher_changed(self, event=None):
        """Реакция на смену шифра: блокируем ключ, обновляем подсказки."""
        cipher_name = self._current_cipher()
        needs_key = cipher_name in (
            "caesar", "vigenere", "playfair", "hill", "xor"
        )

        # Поле ключа включаем только для шифров, которым он нужен.
        self.key_entry.configure(state="normal" if needs_key else "disabled")
        if not needs_key:
            self.key_entry.delete(0, "end")

        self.key_hint.configure(text=KEY_HINTS[cipher_name])
        self._update_status()

    def _on_text_edited(self, event=None):
        """Обновляет строку состояния при вводе текста."""
        self._update_status()

    def _apply(self, decrypt):
        """Общая логика кнопок «Зашифровать» и «Расшифровать»."""
        source = self.input_text.get("1.0", "end-1c")
        key = self.key_entry.get().strip()
        cipher_name = self._current_cipher()

        try:
            result = run_cipher(cipher_name, source, key, decrypt)
        except ValueError as error:
            # Неверный ключ или текст — показываем понятное сообщение.
            messagebox.showerror("Ошибка ввода", str(error))
            self._update_status("Ошибка ввода — проверьте ключ.")
            return

        self._set_result(result)
        self._update_status(
            f"Готово: {len(source)} символов, шифр «{self.cipher_box.get()}», "
            f"ключ «{key}»"
        )

    def _encrypt(self):
        """Шифрует текст и показывает результат."""
        self._apply(decrypt=False)

    def _decrypt(self):
        """Расшифровывает текст и показывает результат."""
        self._apply(decrypt=True)

    def _clear(self):
        """Очищает оба поля и строку состояния."""
        self.input_text.delete("1.0", "end")
        self._set_result("")
        self._update_status("Поля очищены.")

    def _copy_result(self):
        """Копирует результат в буфер обмена."""
        result = self._get_result()
        if not result:
            messagebox.showinfo(
                "Копирование",
                "Сначала получите результат — нечего копировать.",
            )
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(result)
        self._update_status("Результат скопирован в буфер обмена.")

    def _save_result(self):
        """Сохраняет результат в текстовый файл."""
        result = self._get_result()
        if not result:
            messagebox.showinfo(
                "Сохранение",
                "Сначала получите результат — сохранять нечего.",
            )
            return

        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Сохранить результат",
            defaultextension=".txt",
            filetypes=[
                ("Текстовый файл", "*.txt"),
                ("Все файлы", "*.*"),
            ],
            initialfile="result.txt",
        )
        if not path:
            return  # пользователь нажал «Отмена»

        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(result)
        except OSError as error:
            messagebox.showerror(
                "Ошибка", f"Не удалось сохранить файл:\n{error}"
            )
            return
        self._update_status(f"Результат сохранён: {path}")

    def _open_file(self):
        """Загружает текст из выбранного файла в поле ввода.

        Кодировка UTF-8 — в ней сохраняет файлы и сама программа,
        поэтому «круговорот» текста через файл работает без потерь.
        """
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Открыть текстовый файл",
            filetypes=[
                ("Текстовый файл", "*.txt"),
                ("Все файлы", "*.*"),
            ],
        )
        if not path:
            return  # пользователь нажал «Отмена»

        try:
            with open(path, "r", encoding="utf-8") as file:
                content = file.read()
        except (OSError, UnicodeDecodeError) as error:
            messagebox.showerror(
                "Ошибка", f"Не удалось прочитать файл:\n{error}"
            )
            return

        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", content)
        self._update_status(f"Файл загружен: {path}")

    def _break_caesar(self):
        """Взламывает шифр Цезаря без ключа — по частоте букв.

        Это «демонстрация для учителя»: программа перебирает все сдвиги
        и выбирает тот, при котором текст больше всего похож на обычный
        русский (или английский) текст.
        """
        source = self.input_text.get("1.0", "end-1c")

        try:
            shift, plain_text = ciphers.break_caesar(source)
        except ValueError as error:
            messagebox.showerror("Взлом не удался", str(error))
            self._update_status("Взлом не удался — нужен текст с буквами.")
            return

        self._set_result(plain_text)
        self._update_status(
            f"Частотный анализ: подобран сдвиг {shift}. "
            "Именно так шифр Цезаря взламывают без ключа!"
        )

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------

    def _set_result(self, text):
        """Записывает текст в поле результата (только для чтения)."""
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.configure(state="disabled")

    def _get_result(self):
        """Возвращает текущий текст из поля результата."""
        return self.result_text.get("1.0", "end-1c")

    def _update_status(self, message=None):
        """Показывает сообщение или стандартную строку состояния."""
        if message is not None:
            self.status_var.set(message)
            return
        text_length = len(self.input_text.get("1.0", "end-1c"))
        self.status_var.set(
            f"Шифр: {self.cipher_box.get()}  |  "
            f"Длина текста: {text_length} символов"
        )