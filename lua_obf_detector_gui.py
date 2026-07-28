#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lua/Roblox Obfuscation Detector - Interface Gráfica
=====================================================

Interface simples em Tkinter para selecionar um arquivo .lua/.luau/.txt
(ou uma pasta inteira) e ver o veredito do detector sem usar a linha de
comando. Usa o mesmo motor/assinaturas de lua_obf_detector.py.

Uso:
    python3 lua_obf_detector_gui.py
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from tkinter.scrolledtext import ScrolledText

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lua_obf_detector as detector

RULES_PATH = detector.DEFAULT_RULES_PATH


class DetectorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Lua/Roblox Obfuscation Detector")
        self.geometry("820x560")
        self.minsize(640, 420)

        self.rules = None
        self._load_rules()

        self._build_widgets()

    # ------------------------------------------------------------------
    def _load_rules(self):
        try:
            self.rules = detector.load_rules(RULES_PATH)
        except Exception as e:
            messagebox.showerror(
                "Erro ao carregar assinaturas",
                f"Não consegui carregar '{RULES_PATH}':\n{e}\n\n"
                "Verifique se signatures.json está na mesma pasta deste script."
            )
            self.rules = {"tools": []}

    # ------------------------------------------------------------------
    def _build_widgets(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Button(top, text="Selecionar arquivo...", command=self.select_file).pack(side="left")
        ttk.Button(top, text="Selecionar pasta...", command=self.select_folder).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Limpar", command=self.clear_output).pack(side="left", padx=(8, 0))

        self.evidence_var = tk.BooleanVar(value=True)
        self.all_var = tk.BooleanVar(value=False)
        self.advanced_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Mostrar motivos (evidências)", variable=self.evidence_var).pack(side="left", padx=(20, 0))
        ttk.Checkbutton(top, text="Mostrar ranking completo", variable=self.all_var).pack(side="left", padx=(10, 0))
        ttk.Checkbutton(top, text="Análise avançada", variable=self.advanced_var).pack(side="left", padx=(10, 0))

        self.path_label = ttk.Label(self, text="Nenhum arquivo selecionado.", padding=(10, 0))
        self.path_label.pack(fill="x")

        self.progress = ttk.Progressbar(self, mode="indeterminate")

        self.output = ScrolledText(self, wrap="word", font=("Consolas", 10))
        self.output.pack(fill="both", expand=True, padx=10, pady=10)
        self.output.configure(state="disabled")

        self._tag_setup()

    def _tag_setup(self):
        self.output.tag_config("header", foreground="#0a5")
        self.output.tag_config("verdict", foreground="#c40", font=("Consolas", 10, "bold"))
        self.output.tag_config("dim", foreground="#666")
        self.output.tag_config("none", foreground="#999")
        self.output.tag_config("category", foreground="#06c", font=("Consolas", 10, "bold"))

    # ------------------------------------------------------------------
    def select_file(self):
        path = filedialog.askopenfilename(
            title="Selecione um script Lua/Luau",
            filetypes=[("Lua/Luau/Texto", "*.lua *.luau *.txt"), ("Todos os arquivos", "*.*")],
        )
        if path:
            self.path_label.configure(text=path)
            self._run_analysis([path])

    def select_folder(self):
        path = filedialog.askdirectory(title="Selecione uma pasta com scripts")
        if path:
            self.path_label.configure(text=path)
            targets = detector.collect_targets(path)
            if not targets:
                messagebox.showinfo("Nada encontrado", "Nenhum arquivo .lua/.luau/.txt nessa pasta.")
                return
            self._run_analysis(targets)

    def clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    # ------------------------------------------------------------------
    def _run_analysis(self, targets):
        self.progress.pack(fill="x", padx=10)
        self.progress.start(10)
        thread = threading.Thread(target=self._analyze_worker, args=(targets,), daemon=True)
        thread.start()

    def _analyze_worker(self, targets):
        results_text = []
        want_advanced = self.advanced_var.get()
        for path in targets:
            try:
                _, results, stats = detector.analyze_file(path, self.rules)
                adv_report = None
                if want_advanced:
                    try:
                        import advanced_analysis as _adv
                        with open(path, "r", encoding="utf-8", errors="replace") as f:
                            src = f.read()
                        adv_report = _adv.run_advanced_analysis(src, results)
                    except ImportError:
                        adv_report = None
                results_text.append((path, results, stats, None, adv_report))
            except Exception as e:
                results_text.append((path, None, None, str(e), None))
        self.after(0, self._show_results, results_text)

    def _show_results(self, results_text):
        self.progress.stop()
        self.progress.pack_forget()

        self.output.configure(state="normal")
        for path, results, stats, error, adv_report in results_text:
            self.output.insert("end", f"\n=== {os.path.basename(path)} ===\n", "header")

            if error:
                self.output.insert("end", f"  Erro ao analisar: {error}\n", "dim")
                continue

            self.output.insert(
                "end",
                f"  {stats['tamanho_bytes']} bytes | {stats['linhas']} linhas | "
                f"entropia {stats['entropia']} | maior linha {stats['maior_linha']} chars\n",
                "dim",
            )

            if self.all_var.get():
                ranked = sorted(results, key=lambda r: r.confidence, reverse=True)
                top = [r for r in ranked if r.confidence > 0]
                if not top:
                    self.output.insert("end", "  Nenhuma assinatura detectada.\n", "none")
                else:
                    for r in top[:10]:
                        bar = "█" * int(r.confidence // 5)
                        tag = " [watermark]" if r.explicit else ""
                        self.output.insert("end", f"    {r.display_name:<30} {r.confidence:5.1f}%  {bar}{tag}\n")
                        if self.evidence_var.get():
                            for ev in r.evidences:
                                self.output.insert("end", f"        - {ev}\n", "dim")
            else:
                winner = detector.pick_winner(results)
                if winner.confidence < 15 and not winner.explicit:
                    self.output.insert("end", "  Veredito: NAO IDENTIFICADO\n", "none")
                    self.output.insert(
                        "end",
                        "  (nenhuma assinatura conhecida bateu com confiança mínima -- "
                        "pode ser código não ofuscado, ou um obfuscador fora da lista)\n",
                        "dim",
                    )
                else:
                    self.output.insert(
                        "end", f"  Veredito: {winner.display_name}  ->  {winner.confidence:.1f}% de confiança\n", "verdict"
                    )
                    if self.evidence_var.get() and winner.evidences:
                        self.output.insert("end", "  Motivos:\n")
                        for ev in winner.evidences:
                            self.output.insert("end", f"    - {ev}\n", "dim")

            if adv_report is not None:
                self._insert_advanced(adv_report)

    def _insert_advanced(self, report):
        self.output.insert("end", "\n  --- Análise avançada ---\n", "category")
        self.output.insert("end", "  Fingerprint estrutural:\n")
        for l in report.fingerprint.summary_lines():
            self.output.insert("end", f"    {l}\n", "dim")

        scored = sorted(report.category_scores.items(), key=lambda kv: kv[1][0], reverse=True)
        scored = [(n, s) for n, s in scored if s[0] > 0]
        if scored:
            self.output.insert("end", "  Scores por categoria:\n")
            for name, (score, ev) in scored:
                bar = "█" * int(score // 5)
                self.output.insert("end", f"    {name:<24} {score:5.1f}  {bar}\n")
                for e in ev:
                    self.output.insert("end", f"        - {e}\n", "dim")

        if report.techniques:
            self.output.insert("end", "  Técnicas específicas:\n")
            for name, (count, _) in sorted(report.techniques.items(), key=lambda kv: -kv[1][0]):
                self.output.insert("end", f"    - {name}: {count}\n", "dim")

        if report.layer_chain:
            self.output.insert("end", "  Cadeia provável de camadas (ordem de aparição):\n")
            self.output.insert("end", "    " + " -> ".join(report.layer_chain) + "\n", "dim")

        if report.family_no_watermark:
            self.output.insert("end", "  Família provável (só estrutura, ignorando watermark):\n")
            for name, conf in report.family_no_watermark:
                self.output.insert("end", f"    - {name}: {conf:.1f}%\n", "dim")

        self.output.see("end")
        self.output.configure(state="disabled")


def main():
    app = DetectorGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
