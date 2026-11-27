"""Colors and the application stylesheet for the System / Light / Dark themes.

Pure Python (no Qt import) so it can be tested anywhere. The look follows the design canvas: teal means healthy
or primary, orange high, amber medium, blue low. Severity colors keep their meaning in every theme.
"""
from __future__ import annotations

from string import Template

CHOICES = ("system", "light", "dark")

PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#0d1117", "rail": "#0a0d12", "panel": "#151b23", "line": "#1f2833", "inset": "#0f151c",
        "text": "#e6edf3", "sub": "#9aa7b6", "mute": "#8b98a8", "accent": "#3dd6c3", "accentHover": "#58e0d0",
        "onAccent": "#06201c", "trk": "#212b38", "ok": "#3dd6c3", "warn": "#ffa58a", "idle": "#aab6c4",
        "activeBg": "#1b2733", "activeFg": "#ffffff", "btn2Line": "#2c3948", "disabledBg": "#232c38",
        "disabledFg": "#6f7c8b", "hoverBg": "#151d27",
        "critBg": "#2f1a20", "critFg": "#ff8da0", "highBg": "#2d1b16", "highFg": "#ffa58a",
        "medBg": "#2b2412", "medFg": "#ffcb6b", "lowBg": "#16233a", "lowFg": "#9cc0ff",
        "infoBg": "#1a222c", "infoFg": "#a9b5c3",
    },
    "light": {
        "bg": "#f4f7fa", "rail": "#ffffff", "panel": "#ffffff", "line": "#dde4ec", "inset": "#eef2f6",
        "text": "#14202e", "sub": "#526173", "mute": "#5f6e80", "accent": "#0b7a6e", "accentHover": "#0d8f81",
        "onAccent": "#ffffff", "trk": "#e1e8ef", "ok": "#0b7a6e", "warn": "#c2410c", "idle": "#526173",
        "activeBg": "#dff1ee", "activeFg": "#0b5f56", "btn2Line": "#c7d2de", "disabledBg": "#e3e9f0",
        "disabledFg": "#8795a6", "hoverBg": "#eaf0f5",
        "critBg": "#fde2e6", "critFg": "#a1122f", "highBg": "#fde5dc", "highFg": "#9a3412",
        "medBg": "#fdf0cf", "medFg": "#7a5200", "lowBg": "#e0ebfc", "lowFg": "#1d4ed8",
        "infoBg": "#e8edf2", "infoFg": "#44546a",
    },
}

_SEV_KEYS = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}
_mode = "dark"


def normalize(choice: str | None) -> str:
    return choice if choice in CHOICES else "system"


def system_is_light() -> bool:
    """True when Windows apps are set to the light theme. Anything unreadable counts as dark."""
    try:
        import winreg  # Windows only
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 1
    except (ImportError, OSError):
        return False


def resolve(choice: str | None) -> str:
    """Turn a saved choice (system | light | dark) into the palette to use: light or dark."""
    choice = normalize(choice)
    if choice == "system":
        return "light" if system_is_light() else "dark"
    return choice


def current_mode() -> str:
    return _mode


def current() -> dict[str, str]:
    return PALETTES[_mode]


def sev_colors(severity: str, mode: str | None = None) -> tuple[str, str]:
    """(text color, background color) for a severity chip."""
    p = PALETTES[mode or _mode]
    k = _SEV_KEYS.get(severity, "info")
    return p[k + "Fg"], p[k + "Bg"]


def sev_color(severity: str) -> str:
    return sev_colors(severity)[0]


_QSS = Template("""
* { font-family: 'Segoe UI'; }
QMainWindow, QWidget { background: $bg; color: $text; font-size: 13px; }
QLabel { background: transparent; }
QCheckBox, QRadioButton { background: transparent; }
QLabel#sub { color: $sub; }
QLabel#mute { color: $mute; font-size: 12px; }
QLabel#h1 { font-size: 26px; font-weight: 600; }
QLabel#caps { color: $sub; font-size: 11px; font-weight: 600; }
QLabel#score { font-size: 60px; font-weight: 600; }
QLabel#stat { font-size: 26px; font-weight: 600; }
QLabel#code { background: $inset; color: $text; border-radius: 6px; padding: 6px 8px; font-family: Consolas, 'Cascadia Mono', monospace; font-size: 12px; }
QTextEdit#preview { background: $inset; color: $text; border: none; border-radius: 8px; padding: 8px; font-family: Consolas, 'Cascadia Mono', monospace; font-size: 12px; }
QListWidget { background: $panel; color: $text; border: 1px solid $line; border-radius: 10px; padding: 4px; }
QListWidget::item { padding: 8px 10px; border-radius: 6px; }
QListWidget::item:selected { background: $activeBg; color: $activeFg; }
QLabel#cardtitle { font-size: 15px; font-weight: 600; }
QFrame#rail { background: $rail; border: none; border-right: 1px solid $line; }
QFrame#card { background: $panel; border: 1px solid $line; border-radius: 16px; }
QFrame#inset { background: $inset; border: 1px solid $line; border-radius: 12px; }
QToolButton#railbtn { background: transparent; color: $idle; border: none; border-radius: 12px; font-size: 11px; padding: 4px 0; }
QToolButton#railbtn:hover { background: $hoverBg; }
QToolButton#railbtn:checked { background: $activeBg; color: $activeFg; }
QPushButton { background: $accent; color: $onAccent; border: none; padding: 9px 18px; border-radius: 10px; font-weight: 600; }
QPushButton:hover { background: $accentHover; }
QPushButton:disabled { background: $disabledBg; color: $disabledFg; }
QPushButton#secondary { background: transparent; color: $text; border: 1px solid $btn2Line; }
QPushButton#secondary:hover { background: $hoverBg; }
QPushButton#danger { background: transparent; color: $warn; border: 1px solid $warn; }
QPushButton#tab { background: transparent; color: $sub; border: none; padding: 7px 16px; border-radius: 16px; }
QPushButton#tab:hover { background: $hoverBg; }
QPushButton#tab:checked { background: $activeBg; color: $activeFg; }
QPushButton#optioncard { background: $panel; color: $text; border: 2px solid $line; border-radius: 16px; padding: 16px; text-align: left; font-weight: 500; }
QPushButton#optioncard:hover { border-color: $btn2Line; }
QPushButton#optioncard:checked { border-color: $accent; }
QTableWidget { background: $panel; gridline-color: $line; border: 1px solid $line; border-radius: 10px; selection-background-color: $activeBg; selection-color: $activeFg; }
QHeaderView::section { background: $inset; color: $sub; border: none; padding: 7px; font-weight: 600; }
QProgressBar { background: $trk; border: none; border-radius: 4px; max-height: 8px; min-height: 8px; text-align: center; }
QProgressBar::chunk { background: $accent; border-radius: 4px; }
QProgressBar[level="warn"]::chunk { background: $warn; }
QTextEdit, QListWidget, QLineEdit, QSpinBox { background: $panel; border: 1px solid $line; border-radius: 10px; padding: 6px; selection-background-color: $activeBg; selection-color: $activeFg; }
QListWidget::item { padding: 8px; border-radius: 6px; }
QListWidget::item:selected { background: $activeBg; color: $activeFg; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: $btn2Line; border-radius: 5px; min-height: 28px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: $btn2Line; border-radius: 5px; min-width: 28px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QToolTip { background: $panel; color: $text; border: 1px solid $line; padding: 4px 8px; }
QMenu { background: $panel; color: $text; border: 1px solid $line; padding: 6px; }
QMenu::item { padding: 7px 18px; border-radius: 6px; }
QMenu::item:selected { background: $activeBg; color: $activeFg; }
""")


def stylesheet(mode: str) -> str:
    return _QSS.substitute(PALETTES[mode])


def apply(app, choice: str | None) -> str:
    """Resolve the choice, set it as the current palette and restyle the whole application."""
    global _mode
    _mode = resolve(choice)
    app.setStyleSheet(stylesheet(_mode))
    return _mode
