import json

from aegisguard.core import config, settings
from aegisguard.ui import theme


def test_palettes_have_same_keys():
    assert set(theme.PALETTES["dark"]) == set(theme.PALETTES["light"])


def test_stylesheet_fully_substituted():
    for mode in ("dark", "light"):
        css = theme.stylesheet(mode)
        assert "$" not in css
        assert theme.PALETTES[mode]["accent"] in css


def test_choice_normalized():
    assert theme.normalize("dark") == "dark"
    assert theme.normalize("purple") == "system"
    assert theme.normalize(None) == "system"


def test_system_choice_follows_windows(monkeypatch):
    monkeypatch.setattr(theme, "system_is_light", lambda: True)
    assert theme.resolve("system") == "light"
    monkeypatch.setattr(theme, "system_is_light", lambda: False)
    assert theme.resolve("system") == "dark"
    assert theme.resolve("light") == "light"


def test_severity_colors_exist_in_both_themes():
    for mode in ("dark", "light"):
        for sev in ("critical", "high", "medium", "low", "info"):
            fg, bg = theme.sev_colors(sev, mode)
            assert fg.startswith("#") and bg.startswith("#")


def test_theme_setting_is_saved_and_validated(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    s = settings.load()
    assert s.theme == "system"
    s.theme = "light"
    settings.save(s)
    assert settings.load().theme == "light"
    (tmp_path / "settings.json").write_text(json.dumps({"theme": "neon"}), encoding="utf-8")
    assert settings.load().theme == "system"
