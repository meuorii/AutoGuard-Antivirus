"""Windows sidebar geometry regression check; opens a UI without services.

Run from the project root: python -m tools.check_sidebar_layout
"""
import tkinter.font as tkfont
import traceback
import sys
from pathlib import Path
from PIL import ImageGrab

import customtkinter as ctk

from app.ui import theme
from app.ui.sidebar import NAV_ITEMS, Sidebar


def main():
    root = ctk.CTk()
    root.geometry("1080x680")
    root.minsize(1080, 680)
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(0, weight=1)
    callbacks = []
    errors = []
    def report_error(*error):
        errors.append(error)
        traceback.print_exception(*error)
    root.report_callback_exception = report_error
    sidebar = Sidebar(root, callbacks.append)
    sidebar.grid(row=0, column=0, sticky="nsw")
    content = ctk.CTkFrame(root)
    content.grid(row=0, column=1, sticky="nsew")
    original_widgets = (sidebar.brand_title, sidebar.brand_subtitle, *sidebar.buttons.values())
    widths = []
    cases = iter((dpi, setting, size)
                 for dpi in (1.0, 1.25, 1.5, 2.0)
                 for setting in theme.TEXT_SCALES
                 for size in ("1080x680", "1320x820", "maximized"))
    if "--preview" in sys.argv:
        cases = iter([(1.0, "Extra Large", "1080x680")])

    def verify(dpi, setting, size):
        try:
            if size == "maximized" and (root.winfo_width() < 1080 * dpi or root.winfo_height() < 680 * dpi):
                print(f"SKIP {dpi:.0%}, {setting}, maximized: display is smaller than the existing logical minimum", flush=True)
                next_case()
                return
            for label in (sidebar.brand_title, sidebar.brand_subtitle):
                assert label.cget("wraplength") == 0
                assert label._wrap_job is None
                text_width = tkfont.Font(root=root, font=label._label.cget("font")).measure(label.cget("text"))
                assert label.winfo_width() >= text_width, (setting, size, label.cget("text"))
                assert label.winfo_rootx() > sidebar.logo.winfo_rootx() + sidebar.logo.winfo_width(), (dpi, setting, size, label.winfo_geometry(), sidebar.logo.winfo_geometry(), sidebar.brand.winfo_geometry())
                assert label.winfo_rootx() + label.winfo_width() <= sidebar.winfo_rootx() + sidebar.winfo_width()
                assert label._label.winfo_height() < 40 * dpi, "Brand text must stay on one line"
            assert abs(sidebar.brand_title.winfo_rootx() - sidebar.brand_subtitle.winfo_rootx()) <= 1
            assert sidebar.brand.winfo_height() < 90 * dpi, (dpi, setting, size, sidebar.brand.winfo_geometry(), sidebar.brand_title.master.winfo_geometry())
            assert content.winfo_width() >= 700 * dpi, (dpi, size, content.winfo_width())
            assert sidebar.footer.winfo_y() + sidebar.footer.winfo_height() <= sidebar.winfo_height(), (dpi, setting, size, sidebar.footer.winfo_geometry(), sidebar.winfo_geometry())
            previous_bottom = sidebar.brand.winfo_y() + sidebar.brand.winfo_height()
            for key, _ in NAV_ITEMS:
                button = sidebar.buttons[key]
                assert button.winfo_y() >= previous_bottom
                assert button._text_label.winfo_reqwidth() <= button.winfo_width()
                previous_bottom = button.winfo_y() + button.winfo_height()
            assert sidebar.footer.winfo_y() > previous_bottom
            assert sidebar.protection_icon.winfo_rootx() + sidebar.protection_icon.winfo_width() <= sidebar.protection.winfo_rootx()
            assert sidebar.protection.winfo_rootx() + sidebar.protection.winfo_width() <= sidebar.footer.winfo_rootx() + sidebar.footer.winfo_width()
            widths.append(round(sidebar._reverse_widget_scaling(sidebar.winfo_width())))
            assert widths[-1] == widths[0], widths
            assert not errors, errors
            if dpi == 1.0 and setting == "Extra Large" and size == "1080x680":
                screenshot = Path(".pytest_cache/sidebar-branding-hotfix.png")
                screenshot.parent.mkdir(exist_ok=True)
                x, y = sidebar.winfo_rootx(), sidebar.winfo_rooty()
                ImageGrab.grab(bbox=(x, y, x + sidebar.winfo_width(), y + sidebar.winfo_height())).save(screenshot)
                root.attributes("-topmost", False)
            print(f"PASS {dpi:.0%}, {setting}, {size}: sidebar {widths[-1]} logical pixels", flush=True)
            next_case()
        except BaseException:
            root.quit()
            raise

    def next_case():
        try:
            dpi, setting, size = next(cases)
        except StopIteration:
            for key, _ in NAV_ITEMS:
                sidebar.buttons[key].invoke()
            assert callbacks == [key for key, _ in NAV_ITEMS]
            assert original_widgets == (sidebar.brand_title, sidebar.brand_subtitle, *sidebar.buttons.values())
            sidebar.set_active("settings")
            assert sidebar.buttons["settings"].cget("fg_color") == theme.ACCENT_DARK
            print("PASS navigation callbacks, selection, persistent widgets, and callback errors", flush=True)
            root.quit()
            return
        root.state("normal")
        ctk.set_window_scaling(dpi)
        ctk.set_widget_scaling(dpi)
        theme.set_text_size(setting)
        if size == "maximized":
            root.state("zoomed")
        else:
            root.geometry(size + "+20+20")
        if dpi == 1.0 and setting == "Extra Large" and size == "1080x680":
            root.attributes("-topmost", True)
            root.lift()
        sidebar.set_protection("Real-time protection needs attention; check protection settings.", "degraded")
        # CTk restores Windows min/max constraints 1000 ms after a DPI change.
        root.after(1300, lambda: verify(dpi, setting, size))

    try:
        root.after(300, next_case)
        root.mainloop()
        assert not errors, errors
    finally:
        if root.winfo_exists():
            root.destroy()


if __name__ == "__main__":
    main()
