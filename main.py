"""
main.py — точка входа в программу «Шифратор».

Запуск из папки проекта:
    python main.py

Программа открывает окно с графическим интерфейсом. Чтобы закрыть
её, достаточно закрыть окно.
"""

import tkinter as tk

from gui import CipherApp, make_icon


def main():
    """Создаёт главное окно, ставит иконку и запускает программу."""
    root = tk.Tk()

    icon = make_icon(root)
    if icon is not None:
        root.iconphoto(True, icon)

    # Объект приложения живёт всё время работы окна.
    app = CipherApp(root)

    root.mainloop()


if __name__ == "__main__":
    main()