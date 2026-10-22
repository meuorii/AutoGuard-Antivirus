"""Preference and typography regression checks without a display server."""
import pytest
from types import SimpleNamespace

from app.ui import theme
from app.ui.preferences import load_text_size, save_text_size


@pytest.mark.parametrize("auto_wrap, expected_wrap, expected_bindings", [(False, 0, 0), (True, 480, 1)])
def test_brand_labels_can_opt_out_of_responsive_wrapping(monkeypatch, auto_wrap, expected_wrap, expected_bindings):
    options = {}
    bindings = []
    monkeypatch.setattr(theme.ctk.CTkLabel, "__init__", lambda self, master, **kwargs: options.update(kwargs))
    monkeypatch.setattr(theme.tk.Frame, "bind", lambda *args, **kwargs: bindings.append(args))
    label = theme.Label(None, font=object(), auto_wrap=auto_wrap)
    assert options["wraplength"] == expected_wrap
    assert len(bindings) == expected_bindings
    assert label._wrap_job is None


def test_label_wrap_defers_coalesces_and_blocks_recursive_resize():
    class FakeLabel:
        _fit_text = theme.Label._fit_text
        _apply_text_wrap = theme.Label._apply_text_wrap
        _update_text_wrap = theme.Label._update_text_wrap
        _wrap_job = None
        _wrap_updating = False
        _last_wrap_width = None
        _pending_wrap_width = None
        _wrap_limit = 0
        wraplength = 480

        def __init__(self):
            self.jobs = []
            self.changes = []
            self._label = SimpleNamespace(cget=lambda name: 0)

        def _reverse_widget_scaling(self, width):
            return width

        def after(self, delay, callback):
            self.jobs.append(callback)
            return "pending"

        def winfo_manager(self):
            return "grid"

        def grid_info(self):
            return {"sticky": "ew"}

        def cget(self, name):
            return self.wraplength

        def configure(self, **kwargs):
            self.changes.append(kwargs)
            self.wraplength = kwargs["wraplength"]
            # Reproduce Tk delivering another resize during a geometry update.
            self._fit_text(SimpleNamespace(width=300))
            self._apply_text_wrap()

    label = FakeLabel()
    label._fit_text(SimpleNamespace(width=250))
    label._fit_text(SimpleNamespace(width=300))
    assert len(label.jobs) == 1
    assert label.changes == []
    label.jobs.pop()()
    assert label.changes == [{"wraplength": 296}]
    assert label.jobs == []
    assert label._wrap_job is None
    label._fit_text(SimpleNamespace(width=300))
    assert label.jobs == []
    label._fit_text(SimpleNamespace(width=400))
    assert len(label.jobs) == 1


def test_text_contrast_on_existing_surfaces():
    def luminance(color):
        channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
        return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

    for foreground in (theme.TEXT, theme.TEXT_MUTED, theme.TEXT_DIM):
        for background in (theme.BG, theme.SIDEBAR, theme.SURFACE, theme.SURFACE_ALT, theme.SURFACE_HOVER):
            assert (luminance(foreground) + 0.05) / (luminance(background) + 0.05) >= 4.5


def test_preference_defaults_and_round_trip(tmp_path):
    assert load_text_size(tmp_path) == "Large"
    for value in theme.TEXT_SCALES:
        save_text_size(tmp_path, value)
        assert load_text_size(tmp_path) == value
    (tmp_path / "ui-settings.json").write_text("broken", encoding="utf-8")
    assert load_text_size(tmp_path) == "Large"
    (tmp_path / "ui-settings.json").write_text("[]", encoding="utf-8")
    assert load_text_size(tmp_path) == "Large"
    with pytest.raises(ValueError):
        save_text_size(tmp_path, "Tiny")


def test_live_fonts_reuse_objects_and_keep_hierarchy(monkeypatch):
    class FakeFont:
        def __init__(self, **options):
            self.options = options

        def configure(self, **options):
            self.options.update(options)

    monkeypatch.setattr(theme.ctk, "CTkFont", FakeFont)
    monkeypatch.setattr(theme, "_fonts", {})
    original = theme.text_size()
    try:
        body = theme.font()
        heading = theme.font("page", "bold")
        for setting in theme.TEXT_SCALES:
            theme.set_text_size(setting)
            assert theme.font() is body
            assert body.options["size"] >= 16
            assert heading.options["size"] > body.options["size"]
        assert body.options["size"] == 20
        with pytest.raises(ValueError):
            theme.set_text_size("Tiny")
    finally:
        theme.set_text_size(original)
