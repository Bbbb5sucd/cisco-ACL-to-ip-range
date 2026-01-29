#!/usr/bin/env python3
"""Minimal GUI for the Cisco ACL -> IP range converter.

Windows-friendly Tkinter app that wraps the same parser used by acl2range.py.
"""

from __future__ import annotations

import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from acl2range import iter_parsed


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Cisco ACL → IP ranges")
        self.minsize(980, 640)

        self.input_path = tk.StringVar(value="")
        self.output_format = tk.StringVar(value="text")
        self.only = tk.StringVar(value="both")
        self.include_cidr = tk.BooleanVar(value=False)

        self._init_style()
        self._build_ui()

    def _init_style(self) -> None:
        self.configure(background="#0f172a")  # deep slate backdrop
        style = ttk.Style(self)
        style.theme_use("clam")

        # Base fonts
        heading = tkfont.nametofont("TkHeadingFont")
        heading.configure(family="Segoe UI", size=14, weight="bold")
        body = tkfont.nametofont("TkDefaultFont")
        body.configure(family="Segoe UI", size=10)
        mono = tkfont.nametofont("TkFixedFont")
        mono.configure(family="Consolas", size=10)
        self.mono_font = mono

        accent = "#0ea5e9"  # cyan accent
        panel = "#111827"
        text = "#e5e7eb"
        muted = "#9ca3af"

        style.configure("TFrame", background=panel)
        style.configure("TLabel", background=panel, foreground=text)
        style.configure("Heading.TLabel", background=panel, foreground=text, font=heading)
        style.configure("Muted.TLabel", background=panel, foreground=muted)
        style.configure("TEntry", fieldbackground="#0b1220", foreground=text)
        style.configure("TButton", padding=6)
        style.map("Accent.TButton", background=[("active", accent)], foreground=[("active", "#0b1220")])
        style.configure("Accent.TButton", background=accent, foreground="#0b1220", font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", background=panel, foreground=muted)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=14)
        root.grid(row=0, column=0, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        root.columnconfigure(1, weight=1)
        root.rowconfigure(4, weight=1)

        header = ttk.Frame(root)
        header.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text="Cisco ACL → IP ranges", style="Heading.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Parse Cisco ACL lines, visualize ranges, and export as text/JSON.", style="Muted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

        ttk.Label(root, text="Input file:").grid(row=1, column=0, sticky="w")
        path_entry = ttk.Entry(root, textvariable=self.input_path)
        path_entry.grid(row=1, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(root, text="Browse…", command=self._browse).grid(row=1, column=2, sticky="e")

        opts = ttk.Frame(root)
        opts.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(10, 6))
        opts.columnconfigure(6, weight=1)

        ttk.Label(opts, text="Format:").grid(row=0, column=0, sticky="w")
        fmt = ttk.Combobox(opts, textvariable=self.output_format, values=["text", "json", "jsonl"], state="readonly", width=8)
        fmt.grid(row=0, column=1, sticky="w", padx=(6, 18))
        fmt.bind("<<ComboboxSelected>>", lambda _e: self._sync_include_cidr_state())

        ttk.Label(opts, text="Only:").grid(row=0, column=2, sticky="w")
        only = ttk.Combobox(opts, textvariable=self.only, values=["both", "src", "dst"], state="readonly", width=8)
        only.grid(row=0, column=3, sticky="w", padx=(6, 18))

        self.include_cidr_chk = ttk.Checkbutton(opts, text="Include CIDR (JSON/JSONL)", variable=self.include_cidr)
        self.include_cidr_chk.grid(row=0, column=4, sticky="w")

        ttk.Button(opts, text="Convert", command=self._convert, style="Accent.TButton").grid(row=0, column=5, sticky="e", padx=(18, 6))
        ttk.Button(opts, text="Save", command=self._save).grid(row=0, column=6, sticky="e", padx=(6, 6))
        ttk.Button(opts, text="Copy", command=self._copy).grid(row=0, column=7, sticky="e", padx=(6, 6))
        ttk.Button(opts, text="Clear", command=self._clear).grid(row=0, column=8, sticky="e")

        self._sync_include_cidr_state()

        self.output = tk.Text(root, wrap="none", undo=True, background="#0b1220", foreground="#e5e7eb", insertbackground="#e5e7eb")
        self.output.configure(font=self.mono_font, padx=10, pady=8)
        self.output.grid(row=4, column=0, columnspan=3, sticky="nsew")

        yscroll = ttk.Scrollbar(root, orient="vertical", command=self.output.yview)
        yscroll.grid(row=4, column=3, sticky="ns")
        self.output.configure(yscrollcommand=yscroll.set)

        xscroll = ttk.Scrollbar(root, orient="horizontal", command=self.output.xview)
        xscroll.grid(row=5, column=0, columnspan=3, sticky="ew")
        self.output.configure(xscrollcommand=xscroll.set)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(root, textvariable=self.status, style="Status.TLabel").grid(row=6, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _sync_include_cidr_state(self) -> None:
        fmt = self.output_format.get()
        state = "normal" if fmt in ("json", "jsonl") else "disabled"
        self.include_cidr_chk.configure(state=state)
        if state == "disabled":
            self.include_cidr.set(False)

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Cisco ACL file",
            filetypes=[("Text files", "*.txt;*.cfg;*.conf;*.log"), ("All files", "*.*")],
        )
        if path:
            self.input_path.set(path)

    def _read_input(self, path: str) -> str:
        # Try UTF-8, then fall back to system default with replacement.
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()

    def _render(self, text: str) -> str:
        fmt = self.output_format.get()
        only = self.only.get()
        include_cidr = self.include_cidr.get()

        entries = list(iter_parsed(text.splitlines(True)))

        if fmt == "text":
            out_lines: list[str] = []
            for entry in entries:
                proto = entry.protocol or "ip"
                if only in ("src", "both"):
                    out_lines.append(f"{entry.action} {proto} src {entry.src.to_text()}")
                if only in ("dst", "both") and entry.dst is not None:
                    out_lines.append(f"{entry.action} {proto} dst {entry.dst.to_text()}")
            return "\n".join(out_lines) + ("\n" if out_lines else "")

        if fmt == "json":
            data = [e.to_dict(include_cidr=include_cidr) for e in entries]
            return json.dumps(data, indent=2) + "\n"

        # jsonl
        return "\n".join(json.dumps(e.to_dict(include_cidr=include_cidr)) for e in entries) + ("\n" if entries else "")

    def _convert(self) -> None:
        path = self.input_path.get().strip()
        if not path:
            messagebox.showwarning("Missing input", "Choose an input file first.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Not found", f"File does not exist:\n{path}")
            return

        try:
            self.status.set("Converting…")
            self.update_idletasks()
            text = self._read_input(path)
            rendered = self._render(text)
            self.output.delete("1.0", "end")
            self.output.insert("1.0", rendered)
            self.status.set(f"Done ({len(rendered):,} chars)")
        except Exception as e:
            self.status.set("Error")
            messagebox.showerror("Conversion failed", str(e))

    def _save(self) -> None:
        content = self.output.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showwarning("Nothing to save", "Run Convert first.")
            return

        default_ext = {"text": ".txt", "json": ".json", "jsonl": ".jsonl"}.get(self.output_format.get(), ".txt")
        path = filedialog.asksaveasfilename(
            title="Save output",
            defaultextension=default_ext,
            filetypes=[("All files", "*.*")],
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.status.set(f"Saved: {path}")

    def _copy(self) -> None:
        content = self.output.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showwarning("Nothing to copy", "Run Convert first.")
            return
        self.clipboard_clear()
        self.clipboard_append(content)
        self.status.set("Copied to clipboard")

    def _clear(self) -> None:
        self.output.delete("1.0", "end")
        self.status.set("Cleared")


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
