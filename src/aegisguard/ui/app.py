"""Minimal Tkinter dashboard (placeholder; will be replaced by a richer UI)."""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

from ..modules import firewall, health, reports, scanner


def launch() -> None:
    root = tk.Tk()
    root.title("AegisGuard AI")
    root.geometry("760x520")
    ttk.Label(root, text="AegisGuard AI", font=("Segoe UI", 18, "bold")).pack(pady=8)
    out = scrolledtext.ScrolledText(root, wrap="word", font=("Consolas", 10))
    out.pack(fill="both", expand=True, padx=10, pady=6)

    def run(fn_list, label):
        def work():
            out.insert("end", f"Running {label}...\n")
            merged = reports.merge([f() for f in fn_list])
            for f in merged.findings:
                out.insert("end", f"[{f.severity.value.upper()}] {f.module}: {f.title} {f.detail}\n")
            md, _ = reports.write(merged)
            out.insert("end", f"Done. {len(merged.findings)} finding(s). Report: {md}\n\n")
        threading.Thread(target=work, daemon=True).start()

    bar = ttk.Frame(root)
    bar.pack(pady=6)
    for text, fns in [("Health", [health.run]), ("Quick Scan", [scanner.run]),
                      ("Firewall", [firewall.run]), ("Full Check", [health.run, scanner.run, firewall.run])]:
        ttk.Button(bar, text=text, command=lambda f=fns, t=text: run(f, t)).pack(side="left", padx=4)
    root.mainloop()
