"""
PISCES ASCII banner.

Usage:
    from src.utils.banner import BANNER
    console.print(BANNER)
"""

from rich.text import Text


def _make_banner() -> Text:
    _BODY_SPLIT = 21  # blue | red boundary for lines 3-13
    _TEXT_SPLIT = 57  # red | green boundary for lines 6-13
    _TAIL_SPLIT = 31  # blue | red boundary for lines 14-17

    _lines = [
        "\n"
        # 0-2: pure blue
        "              ███████",
        "          ███████████",
        # 2-5: blue | red
        "        ████████ ████    ████████████",
        "      ███████████████  ███████     ██████",
        "     ███████████████     ███         ██████",
        "  █████████████████                   █  ████",
        # 6-13: blue | red | green
        " ██ ████████   ███                     █ █████           ██████████    ██     █████████     ██████████   ██████████    █████████",
        "███████████   ███                      █  █████          ██       ██   ██   ███           ███       ██   ██          ███",
        "██████████   ████                      █  ██████         ██       ███  ██   ███          ██              ██          ███",
        "█████████   ██ █                       █  ██████   █     ██       ██   ██     ███████    ██              █████████     ███████",
        "   ██████  ██                      ██ █   ██████ ███     ██████████    ██           ███  ██              ██                  ███",
        "    █████  ██                     █████   ██████ ███     ██            ██            ██  ███        ██   ██                   ██",
        "    █████  ██                     ███    ███████ ██      ██            ██   ████   ████    ████   ████   ██          ████   ████",
        "     █████ ██                     ███   ██████████       ██            ██      █████          █████      ██████████     █████",
        # 14-17: blue | red
        "       ████ ██                  ███████████████ █",
        "        ███████         ███    ███████████████",
        "           █████      ███████  ██████████████",
        "              █████████████    ████ ████████",
        # 18-19: pure red
        "                               ██████████",
        "                               ███████",
    ]

    t = Text()
    for i, line in enumerate(_lines):
        if i < 2:
            t.append(line, style="blue")
        elif i < 6:
            t.append(line[:_BODY_SPLIT], style="blue")
            t.append(line[_BODY_SPLIT:], style="red")
        elif i < 14:
            t.append(line[:_BODY_SPLIT], style="blue")
            t.append(line[_BODY_SPLIT:_TEXT_SPLIT], style="red")
            t.append(line[_TEXT_SPLIT:], style="white")
        elif i < 18:
            t.append(line[:_TAIL_SPLIT], style="blue")
            t.append(line[_TAIL_SPLIT:], style="red")
        else:
            t.append(line, style="red")
        t.append("\n")
    return t


BANNER = _make_banner()
