BG = "#0C1012"; SIDEBAR = "#111619"; SURFACE = "#151B1E"; SURFACE_ALT = "#1A2125"; SURFACE_HOVER = "#303E44"; BORDER = "#45565E"; TEXT = "#F5F7F8"; TEXT_MUTED = "#BAC5CB"; TEXT_DIM = "#AAB8BF"
ACCENT = "#55D6C2"; ACCENT_HOVER = "#45C5B2"; ACCENT_DARK = "#173A35"; DANGER = "#F07178"; DANGER_DARK = "#3A1E21"; WARNING = "#E1B65F"; WARNING_DARK = "#3A311D"; INFO = "#71A7E8"; INFO_DARK = "#1A2D43"; SUCCESS = "#67D59C"; SUCCESS_DARK = "#18392B"

FONT = "Segoe UI"; FONT_MONO = "Cascadia Mono"; RADIUS = 12; RADIUS_SMALL = 8; SIDEBAR_WIDTH = 280

STATUS_COLORS = {
    "running": (SUCCESS, SUCCESS_DARK), "protected": (SUCCESS, SUCCESS_DARK), "verified": (SUCCESS, SUCCESS_DARK), "contained": (SUCCESS, SUCCESS_DARK), "completed": (SUCCESS, SUCCESS_DARK),
    "degraded": (WARNING, WARNING_DARK), "partial": (WARNING, WARNING_DARK), "suspicious": (WARNING, WARNING_DARK), "investigating": (WARNING, WARNING_DARK), "reappeared": (WARNING, WARNING_DARK),
    "dangerous": (DANGER, DANGER_DARK), "failed": (DANGER, DANGER_DARK), "error": (DANGER, DANGER_DARK),
    "stopped": (TEXT_MUTED, SURFACE_ALT), "idle": (TEXT_MUTED, SURFACE_ALT), "open": (INFO, INFO_DARK), "restored": (INFO, INFO_DARK),
}

# CTkFont sizes are logical pixels; CustomTkinter retains Windows DPI handling.
import customtkinter as ctk
import weakref
import tkinter as tk

TYPE_SIZES = {"page": 28, "section": 22, "card": 19, "body": 16,
              "secondary": 15, "button": 17, "warning": 18,
              "brand_title": 20, "brand_subtitle": 12}
TEXT_SCALES = {"Standard": 1.0, "Large": 1.125, "Extra Large": 1.25}
_text_size = "Large"
_fonts = weakref.WeakValueDictionary()


def set_text_size(value):
    global _text_size
    if value not in TEXT_SCALES:
        raise ValueError("Unknown text size")
    _text_size = value
    for (role, weight, family), item in list(_fonts.items()):
        item.configure(size=round(TYPE_SIZES[role] * TEXT_SCALES[value]))


def text_size():
    return _text_size


def font(role="body", weight="normal", family=FONT):
    key = (role, weight, family)
    item = _fonts.get(key)
    if item is None:
        item = ctk.CTkFont(family=family, size=round(TYPE_SIZES[role] * TEXT_SCALES[_text_size]), weight=weight)
        _fonts[key] = item
    return item


class Label(ctk.CTkLabel):
    """Wrap within the allocated column rather than a fixed screen width."""
    def __init__(self, master, *, auto_wrap=True, **kwargs):
        if "font" not in kwargs:
            kwargs["font"] = font()
        self._wrap_limit = kwargs.get("wraplength", 0)
        self._wrap_job = None
        self._wrap_updating = False
        self._last_wrap_width = None
        self._pending_wrap_width = None
        if auto_wrap:
            kwargs.setdefault("wraplength", 480)
        else:
            kwargs["wraplength"] = 0
        super().__init__(master, **kwargs)
        if auto_wrap:
            tk.Frame.bind(self, "<Configure>", self._fit_text, add="+")

    def _fit_text(self, event):
        # Wrapping can trigger further geometry events while Tk is resizing.
        # Never change geometry directly from the Configure event's stack.
        if self._wrap_updating:
            return
        width = int(self._reverse_widget_scaling(event.width))
        if width == self._last_wrap_width:
            return  # Height-only changes do not require another wrap update.
        self._pending_wrap_width = width
        if self._wrap_job is None:
            self._wrap_job = self.after(16, self._apply_text_wrap)

    def _apply_text_wrap(self):
        if self._wrap_updating:
            return
        self._wrap_job = None
        self._wrap_updating = True
        try:
            self._update_text_wrap()
        finally:
            self._wrap_updating = False

    def _update_text_wrap(self):
        self._last_wrap_width = self._pending_wrap_width
        manager = self.winfo_manager()
        if manager == "grid":
            sticky = self.grid_info().get("sticky", "")
            if "e" not in sticky or "w" not in sticky:
                return
        elif manager == "pack":
            if self.pack_info().get("fill") not in {"x", "both"}:
                return
        else:
            return
        padding = int(self._label.cget("padx")) * 2
        width = max(24, self._pending_wrap_width - padding - 4)
        target = min(width, self._wrap_limit) if self._wrap_limit else width
        if abs(self.cget("wraplength") - target) > 2:
            self.configure(wraplength=target)

    def destroy(self):
        if self._wrap_job is not None:
            self.after_cancel(self._wrap_job)
            self._wrap_job = None
        super().destroy()

    def pack(self, **kwargs):
        if kwargs.get("side", "top") in {"top", "bottom"}:
            kwargs.setdefault("fill", "x")
        return super().pack(**kwargs)


class Button(ctk.CTkButton):
    """Larger targets with keyboard activation and a visible focus border."""
    def __init__(self, master, **kwargs):
        if "font" not in kwargs:
            kwargs["font"] = font("button")
        kwargs["height"] = max(44, kwargs.get("height", 44))
        kwargs.setdefault("text_color_disabled", TEXT_DIM)
        if kwargs.get("fg_color") == DANGER:
            kwargs.update(hover_color="#FF8D94", text_color=BG)
        elif kwargs.get("fg_color") == DANGER_DARK:
            kwargs["hover_color"] = "#552B31"
        elif kwargs.get("fg_color") == ACCENT_DARK:
            kwargs["hover_color"] = "#24564E"
        super().__init__(master, **kwargs)
        tk.Frame.configure(self, takefocus=0)
        self._canvas.configure(takefocus=1)
        self.bind("<Return>", lambda event: self.invoke(), add="+")
        self.bind("<space>", lambda event: self.invoke(), add="+")
        self.bind("<FocusIn>", self._focus_in, add="+")
        self.bind("<FocusOut>", self._focus_out, add="+")

    def _focus_in(self, event):
        self._saved_border = (self.cget("border_width"), self.cget("border_color"))
        self.configure(border_width=2, border_color=TEXT)
        parent = self.master
        while parent is not None:
            if isinstance(parent, ctk.CTkScrollableFrame):
                canvas = parent._parent_canvas
                bounds = canvas.bbox("all")
                if bounds and bounds[3] > canvas.winfo_height():
                    top = self.winfo_rooty() - parent.winfo_rooty()
                    visible = canvas.canvasy(0)
                    if top < visible or top + self.winfo_height() > visible + canvas.winfo_height():
                        canvas.yview_moveto(max(0, top - 12) / bounds[3])
                break
            parent = getattr(parent, "master", None)

    def _focus_out(self, event):
        if hasattr(self, "_saved_border"):
            self.configure(border_width=self._saved_border[0], border_color=self._saved_border[1])

    def focus_set(self):
        self._canvas.focus_set()
