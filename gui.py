#!/usr/bin/env python3
"""
Incompetent Bastard — GUI launcher
Vervangt gui.sh + dmenu-mac met een tkinter launcher.
Geen externe dependencies — alleen stdlib.

Gebruik:
    python3 gui.py [--port 5000]
"""

import argparse
import os
import platform
import subprocess
import sys
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox

# ── Paden ────────────────────────────────────────────────────────────────

ROOT = Path(__file__).parent.resolve()
SCREENSHOTS_DIR = ROOT / "raw" / "screenshots"
COMMANDS_DIR = ROOT / "http" / "commands"
LATEX_DIR = ROOT / "meuk" / "gui" / "latex"
SHELLS_FILE = ROOT / "http" / "payloads" / "shell_443.txt"

# ── Kleuren (donker thema) ────────────────────────────────────────────────

BG = "#0f172a"
BG2 = "#1e293b"
BG3 = "#334155"
FG = "#f1f5f9"
FG_MUTED = "#94a3b8"
ACCENT = "#3b82f6"
ACCENT_HOVER = "#2563eb"
SUCCESS = "#22c55e"
DANGER = "#ef4444"
BORDER = "#475569"


# ── Hulpfuncties ─────────────────────────────────────────────────────────

def _copy_to_clipboard(root, text: str):
    """Kopieer tekst naar klembord via tkinter."""
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()


def _open_browser(url: str):
    webbrowser.open(url)


def _dashboard_url(port: int, path: str = "") -> str:
    return f"http://127.0.0.1:{port}{path}"


# ── Picker popup (vervangt dmenu-mac) ────────────────────────────────────

class PickerWindow(tk.Toplevel):
    """
    Zoekbaar keuzescherm voor bestanden uit een directory.
    Geeft de geselecteerde bestandsnaam terug via self.result.
    Gebruik: wacht op destroy, lees dan self.result.
    """

    def __init__(self, parent, title: str, directory: Path):
        super().__init__(parent)
        self.title(title)
        self.result = None
        self._directory = directory
        self._all_files = sorted(
            f.name for f in directory.iterdir() if f.is_file() and not f.name.startswith(".")
        )

        self.configure(bg=BG)
        self.resizable(False, False)
        self.geometry("520x420")
        self._center(parent)
        self.grab_set()

        self._build()
        self._filter_list("")

        self.bind("<Escape>", lambda _e: self.destroy())

    def _center(self, parent):
        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2
        py = parent.winfo_rooty() + parent.winfo_height() // 2
        self.geometry(f"+{px - 260}+{py - 210}")

    def _build(self):
        # Zoekbalk
        top = tk.Frame(self, bg=BG, padx=12, pady=10)
        top.pack(fill="x")
        tk.Label(top, text="Zoeken:", bg=BG, fg=FG_MUTED,
                 font=("monospace", 10)).pack(side="left")
        self._var = tk.StringVar()
        self._var.trace_add("write", lambda *_: self._filter_list(self._var.get()))
        entry = tk.Entry(top, textvariable=self._var, bg=BG2, fg=FG,
                         insertbackground=FG, relief="flat",
                         font=("monospace", 11), bd=4)
        entry.pack(side="left", fill="x", expand=True, padx=(8, 0))
        entry.focus_set()
        entry.bind("<Return>", lambda _e: self._confirm())
        entry.bind("<Down>", lambda _e: self._move(1))
        entry.bind("<Up>", lambda _e: self._move(-1))

        # Lijst
        mid = tk.Frame(self, bg=BG, padx=12)
        mid.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(mid, bg=BG3, troughcolor=BG2,
                                  activebackground=ACCENT, relief="flat")
        scrollbar.pack(side="right", fill="y")

        self._listbox = tk.Listbox(
            mid,
            bg=BG2, fg=FG, selectbackground=ACCENT, selectforeground=FG,
            activestyle="none", relief="flat", bd=0,
            font=("monospace", 10),
            yscrollcommand=scrollbar.set,
        )
        self._listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self._listbox.yview)
        self._listbox.bind("<Double-Button-1>", lambda _e: self._confirm())
        self._listbox.bind("<Return>", lambda _e: self._confirm())

        # Knoppen
        bot = tk.Frame(self, bg=BG, padx=12, pady=10)
        bot.pack(fill="x")
        _btn(bot, "Kopieer", self._confirm, bg=ACCENT).pack(side="right", padx=(4, 0))
        _btn(bot, "Annuleer", self.destroy, bg=BG3).pack(side="right")

    def _filter_list(self, query: str):
        q = query.strip().lower()
        self._listbox.delete(0, "end")
        for name in self._all_files:
            if q in name.lower():
                self._listbox.insert("end", name)
        if self._listbox.size() > 0:
            self._listbox.selection_set(0)

    def _move(self, delta: int):
        sel = self._listbox.curselection()
        idx = (sel[0] if sel else -1) + delta
        idx = max(0, min(idx, self._listbox.size() - 1))
        self._listbox.selection_clear(0, "end")
        self._listbox.selection_set(idx)
        self._listbox.see(idx)

    def _confirm(self):
        sel = self._listbox.curselection()
        if not sel:
            return
        self.result = self._listbox.get(sel[0])
        self.destroy()


# ── Schermafdruk (macOS screencapture) ───────────────────────────────────

def _do_screenshot(root: tk.Tk):
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{int(time.time())}.png"
    path = SCREENSHOTS_DIR / filename

    system = platform.system()
    if system == "Darwin":
        cmd = ["screencapture", "-i", str(path)]
    elif system == "Linux":
        # gnome-screenshot of scrot als fallback
        if subprocess.run(["which", "gnome-screenshot"],
                          capture_output=True).returncode == 0:
            cmd = ["gnome-screenshot", "-a", "-f", str(path)]
        else:
            cmd = ["scrot", "-s", str(path)]
    else:
        messagebox.showinfo("Screenshot",
                            "Screenshot niet ondersteund op dit platform.\n"
                            f"Sla handmatig op in:\n{SCREENSHOTS_DIR}")
        return

    try:
        result = subprocess.run(cmd, timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        messagebox.showerror("Screenshot mislukt", str(e))
        return

    if result.returncode != 0 or not path.exists():
        # Gebruiker annuleerde screencapture
        return

    latex_snippet = f"\\plaatje{{{filename}}}{{}}"
    _copy_to_clipboard(root, latex_snippet)
    _show_toast(root, f"Screenshot: {filename}\nLaTeX gekopieerd")


# ── Commando picker ───────────────────────────────────────────────────────

def _do_commands(root: tk.Tk):
    if not COMMANDS_DIR.exists():
        messagebox.showwarning("Commands", f"Map niet gevonden:\n{COMMANDS_DIR}")
        return
    picker = PickerWindow(root, "Commando kiezen", COMMANDS_DIR)
    root.wait_window(picker)
    if not picker.result:
        return
    content = (COMMANDS_DIR / picker.result).read_text(errors="replace").strip()
    _copy_to_clipboard(root, content)
    _show_toast(root, f"Gekopieerd: {picker.result}")


# ── LaTeX snippets picker ─────────────────────────────────────────────────

def _do_latex(root: tk.Tk):
    if not LATEX_DIR.exists():
        messagebox.showwarning("LaTeX", f"Map niet gevonden:\n{LATEX_DIR}")
        return
    picker = PickerWindow(root, "LaTeX snippet kiezen", LATEX_DIR)
    root.wait_window(picker)
    if not picker.result:
        return
    content = (LATEX_DIR / picker.result).read_text(errors="replace").strip()
    _copy_to_clipboard(root, content)
    _show_toast(root, f"Gekopieerd: {picker.result}")


# ── Shells bestand openen ─────────────────────────────────────────────────

def _do_shells():
    if not SHELLS_FILE.exists():
        messagebox.showwarning("Shells",
                               f"Bestand niet gevonden:\n{SHELLS_FILE}\n\n"
                               "Genereer eerst een shell via het dashboard.")
        return
    system = platform.system()
    if system == "Darwin":
        subprocess.Popen(["open", "-t", str(SHELLS_FILE)])
    elif system == "Linux":
        for editor in ("xdg-open", "gedit", "nano"):
            if subprocess.run(["which", editor], capture_output=True).returncode == 0:
                subprocess.Popen([editor, str(SHELLS_FILE)])
                break
    else:
        os.startfile(str(SHELLS_FILE))


# ── Toast notificatie ─────────────────────────────────────────────────────

def _show_toast(root: tk.Tk, message: str, duration_ms: int = 2200):
    """Kleine overlay-melding die na `duration_ms` verdwijnt."""
    toast = tk.Toplevel(root)
    toast.overrideredirect(True)
    toast.attributes("-topmost", True)
    toast.configure(bg=BG2)

    tk.Label(
        toast, text=message, bg=BG2, fg=SUCCESS,
        font=("monospace", 10), padx=16, pady=10,
        justify="left",
    ).pack()

    # Positioneer rechtsonder in het root-venster
    toast.update_idletasks()
    rx = root.winfo_rootx() + root.winfo_width() - toast.winfo_width() - 12
    ry = root.winfo_rooty() + root.winfo_height() - toast.winfo_height() - 12
    toast.geometry(f"+{rx}+{ry}")

    toast.after(duration_ms, toast.destroy)


# ── Widget helpers ────────────────────────────────────────────────────────

def _btn(parent, text: str, command, bg: str = BG2,
         fg: str = FG, width: int = 0) -> tk.Button:
    b = tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg, activebackground=ACCENT_HOVER, activeforeground=FG,
        relief="flat", cursor="hand2",
        font=("monospace", 10, "bold"),
        padx=14, pady=8,
        width=width,
    )
    b.bind("<Enter>", lambda _e: b.config(bg=ACCENT_HOVER))
    b.bind("<Leave>", lambda _e: b.config(bg=bg))
    return b


def _section(parent, label: str) -> tk.Frame:
    tk.Label(parent, text=label, bg=BG, fg=FG_MUTED,
             font=("monospace", 9)).pack(anchor="w", padx=16, pady=(14, 2))
    sep = tk.Frame(parent, bg=BORDER, height=1)
    sep.pack(fill="x", padx=16, pady=(0, 8))
    frame = tk.Frame(parent, bg=BG)
    frame.pack(fill="x", padx=16, pady=(0, 4))
    return frame


# ── Hoofdvenster ─────────────────────────────────────────────────────────

def build_gui(port: int):
    root = tk.Tk()
    root.title("Incompetent Bastard")
    root.configure(bg=BG)
    root.resizable(False, False)

    # ── Header ──────────────────────────────────────────────────────────
    header = tk.Frame(root, bg=ACCENT, padx=16, pady=10)
    header.pack(fill="x")
    tk.Label(header, text="Incompetent Bastard",
             bg=ACCENT, fg=FG, font=("monospace", 13, "bold")).pack(side="left")
    tk.Label(header, text=f":{port}",
             bg=ACCENT, fg="#bfdbfe", font=("monospace", 10)).pack(side="left", padx=(4, 0))

    # ── Dashboard ────────────────────────────────────────────────────────
    f = _section(root, "DASHBOARD")
    row1 = tk.Frame(f, bg=BG)
    row1.pack(fill="x")
    _btn(row1, "Dashboard",
         lambda: _open_browser(_dashboard_url(port)),
         bg=ACCENT, width=14).pack(side="left", padx=(0, 6))
    _btn(row1, "Findings",
         lambda: _open_browser(_dashboard_url(port, "/dashboard/findings")),
         width=14).pack(side="left", padx=(0, 6))
    _btn(row1, "Notes",
         lambda: _open_browser(_dashboard_url(port, "/dashboard/notes")),
         width=14).pack(side="left")

    row2 = tk.Frame(f, bg=BG)
    row2.pack(fill="x", pady=(6, 0))
    _btn(row2, "Tasks",
         lambda: _open_browser(_dashboard_url(port, "/dashboard/tasks")),
         width=14).pack(side="left", padx=(0, 6))
    _btn(row2, "Agents",
         lambda: _open_browser(_dashboard_url(port, "/dashboard/agents")),
         width=14).pack(side="left", padx=(0, 6))
    _btn(row2, "Checklists",
         lambda: _open_browser(_dashboard_url(port, "/dashboard/checklists")),
         width=14).pack(side="left")

    row3 = tk.Frame(f, bg=BG)
    row3.pack(fill="x", pady=(6, 0))
    _btn(row3, "Rapport",
         lambda: _open_browser(_dashboard_url(port, "/dashboard/rapport")),
         width=14).pack(side="left", padx=(0, 6))
    _btn(row3, "Commands",
         lambda: _open_browser(_dashboard_url(port, "/dashboard/commands")),
         width=14).pack(side="left")

    # ── Operationeel ─────────────────────────────────────────────────────
    f2 = _section(root, "OPERATIONEEL")
    row4 = tk.Frame(f2, bg=BG)
    row4.pack(fill="x")
    _btn(row4, "Screenshot",
         lambda: _do_screenshot(root),
         bg="#7c3aed", width=14).pack(side="left", padx=(0, 6))
    _btn(row4, "Commando's",
         lambda: _do_commands(root),
         bg="#7c3aed", width=14).pack(side="left", padx=(0, 6))
    _btn(row4, "LaTeX snippet",
         lambda: _do_latex(root),
         bg="#7c3aed", width=14).pack(side="left")

    row5 = tk.Frame(f2, bg=BG)
    row5.pack(fill="x", pady=(6, 0))
    _btn(row5, "Shells openen",
         _do_shells,
         bg="#7c3aed", width=14).pack(side="left")

    # ── Footer ───────────────────────────────────────────────────────────
    footer = tk.Frame(root, bg=BG, pady=12)
    footer.pack(fill="x")
    tk.Label(footer, text="ESC of sluit venster om te sluiten",
             bg=BG, fg=FG_MUTED, font=("monospace", 8)).pack()

    root.bind("<Escape>", lambda _e: root.destroy())

    # Centreer op scherm
    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    root.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")

    root.mainloop()


# ── Entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Incompetent Bastard GUI launcher")
    parser.add_argument("--port", type=int, default=5000,
                        help="Flask poort (default: 5000)")
    args = parser.parse_args()
    build_gui(args.port)
