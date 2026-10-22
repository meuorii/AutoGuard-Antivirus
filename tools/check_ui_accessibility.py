"""Manual Windows layout smoke check; opens a temporary UI without services."""
import customtkinter as ctk

from app.ui import theme
from app.ui.main_window import PAGE_CLASSES
from app.ui.sidebar import Sidebar
from app.ui.components.dialogs import ConfirmDialog, RestoreDialog
from app.ui.threat_details_page import ThreatDetailsView
from app.ui.quarantine_details_page import QuarantineDetailsView


class Controller:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def main():
    root = ctk.CTk()
    root.geometry("1080x680")
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(0, weight=1)
    Sidebar(root, lambda key: None).grid(row=0, column=0, sticky="nsw")
    container = ctk.CTkFrame(root)
    container.grid(row=0, column=1, sticky="nsew")
    container.grid_columnconfigure(0, weight=1)
    container.grid_rowconfigure(0, weight=1)
    errors = []
    root.report_callback_exception = lambda *error: errors.append(error)
    controller = Controller()
    pages = [page(container, controller) for page in PAGE_CLASSES.values()]
    try:
        for page in pages:
            page.grid(row=0, column=0, sticky="nsew")
        by_name = dict(zip(PAGE_CLASSES, pages))
        path = "C:/Users/Example/Downloads/" + "long-folder-name/" * 8 + "example.exe"
        by_name["threats"]._render([{"section": "Needs attention", "name": "Example threat", "location": path}])
        by_name["quarantine"]._render_list({"isolated_count": 1, "items": [{"name": "Example file", "original_location": path}]})
        settings = by_name["settings"]
        service = {"available": True, "running": True, "status": "Running"}
        settings._loading = False
        settings._data = {
            "protection": {"real_time": service, "usb": service, "scheduled": service,
                           "startup_scan": {"status": "Enabled", "detail": "Scans on startup."}},
            "schedule": {"quick_hours": 24, "full_days": 7},
            "scan_preferences": {"max_file_size_bytes": 1024, "monitor_paths": [path]},
            "quarantine": {"retention": "Until restored or deleted", "detail": "Files remain isolated."},
            "application": {"logs_dir": path, "data_dir": path, "configuration_note": "Settings apply to this application."},
            "advanced": {"database": path, "quarantine_storage": path},
        }
        settings._render()
        for dpi in (1.0, 1.25, 1.5, 2.0):
            ctk.set_widget_scaling(dpi)
            for setting in theme.TEXT_SCALES:
                theme.set_text_size(setting)
                for page in pages:
                    page.tkraise()
                    root.update()
            print(f"Page construction and live scaling OK: {dpi}")
        ctk.set_widget_scaling(1.0)
        for view_class, kwargs in (
            (ThreatDetailsView, {"on_back": lambda: None}),
            (QuarantineDetailsView, {"on_back": lambda: None, "on_verify": lambda: None,
                                     "on_restore": lambda: None, "on_delete": lambda: None}),
        ):
            page = by_name["quarantine"]
            page.clear_body()
            view = view_class(page.body, {"name": "Example threat", "original_location": path}, **kwargs)
            view.grid(row=0, column=0, sticky="ew")
            page.tkraise()
            root.update()
            view.destroy()
        print("Populated cards, settings, and detail views OK")
        for dialog in (ConfirmDialog(root, "Delete file?", "Critical warning: this action permanently deletes the isolated file. " * 3),
                       RestoreDialog(root, "C:/example/file.txt", lambda value: None)):
            root.update()
            dialog.destroy()
        # Exercise deferred wrapping in mainloop, including destruction before
        # its timer fires, rather than relying only on synchronous update().
        temporary = theme.Label(container, text="Pending wrap " * 40)
        temporary.grid(row=1, column=0, sticky="ew")
        root.update_idletasks()
        temporary.destroy()
        def resize_step(index=0):
            if index == 12:
                root.after(200, root.quit)
                return
            root.geometry("1080x680" if index % 2 else "1320x820")
            theme.set_text_size(tuple(theme.TEXT_SCALES)[index % 3])
            root.after(30, lambda: resize_step(index + 1))
        root.after(0, resize_step)
        root.mainloop()
        assert not errors, errors
        print("Dialogs, resize mainloop, timer cancellation, and callbacks OK")
    finally:
        root.destroy()


if __name__ == "__main__":
    main()
