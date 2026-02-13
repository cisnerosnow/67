"""
Comparador de archivos - Analiza encoding, BOM, line endings,
caracteres ocultos y diferencias byte a byte entre dos archivos.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import chardet
import os
import unicodedata
import hashlib
from collections import Counter


# ── BOM signatures ──────────────────────────────────────────────
BOM_SIGNATURES = [
    (b"\xef\xbb\xbf",       "UTF-8 BOM"),
    (b"\xff\xfe\x00\x00",   "UTF-32 LE BOM"),
    (b"\x00\x00\xfe\xff",   "UTF-32 BE BOM"),
    (b"\xff\xfe",            "UTF-16 LE BOM"),
    (b"\xfe\xff",            "UTF-16 BE BOM"),
]


def detect_bom(raw: bytes) -> str:
    for sig, name in BOM_SIGNATURES:
        if raw.startswith(sig):
            return name
    return "Sin BOM"


def detect_line_endings(raw: bytes) -> dict:
    crlf = raw.count(b"\r\n")
    cr = raw.count(b"\r") - crlf
    lf = raw.count(b"\n") - crlf
    return {"CRLF (\\r\\n)": crlf, "LF (\\n)": lf, "CR (\\r)": cr}


def detect_encoding(raw: bytes) -> dict:
    result = chardet.detect(raw)
    return {
        "encoding": result.get("encoding", "Desconocido"),
        "confianza": f"{result.get('confidence', 0) * 100:.1f}%",
        "idioma": result.get("language", "N/A") or "N/A",
    }


def get_hash(raw: bytes) -> dict:
    return {
        "MD5": hashlib.md5(raw).hexdigest(),
        "SHA-1": hashlib.sha1(raw).hexdigest(),
        "SHA-256": hashlib.sha256(raw).hexdigest(),
    }


def find_non_printable(raw: bytes, encoding: str) -> list:
    """Encuentra caracteres no imprimibles / invisibles."""
    found = []
    try:
        text = raw.decode(encoding or "utf-8", errors="replace")
    except (LookupError, UnicodeDecodeError):
        text = raw.decode("utf-8", errors="replace")

    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp == 0xFEFF:
            continue  # BOM, ya se reporta aparte
        cat = unicodedata.category(ch)
        # Cc=control, Cf=format, Co=private use, Zl/Zp=line/paragraph sep
        if cat.startswith("C") or cat in ("Zl", "Zp"):
            if ch in ("\n", "\r", "\t"):
                continue
            name = unicodedata.name(ch, f"U+{cp:04X}")
            found.append((i, cp, name, cat))
    return found


def find_homoglyphs(raw: bytes, encoding: str) -> list:
    """Detecta caracteres que parecen ASCII pero no lo son (homoglifos)."""
    found = []
    try:
        text = raw.decode(encoding or "utf-8", errors="replace")
    except (LookupError, UnicodeDecodeError):
        text = raw.decode("utf-8", errors="replace")

    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp > 127:
            cat = unicodedata.category(ch)
            if cat.startswith("L") or cat.startswith("N") or cat.startswith("P") or cat.startswith("S"):
                name = unicodedata.name(ch, f"U+{cp:04X}")
                found.append((i, ch, cp, name))
    return found


def byte_frequency(raw: bytes) -> Counter:
    return Counter(raw)


def analyze_file(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()

    enc_info = detect_encoding(raw)
    encoding = enc_info["encoding"]

    return {
        "nombre": os.path.basename(path),
        "ruta": path,
        "tamano_bytes": len(raw),
        "bom": detect_bom(raw),
        "encoding": enc_info,
        "line_endings": detect_line_endings(raw),
        "hashes": get_hash(raw),
        "no_imprimibles": find_non_printable(raw, encoding),
        "homoglifos": find_homoglyphs(raw, encoding),
        "byte_freq": byte_frequency(raw),
        "raw": raw,
        "num_lineas": raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0),
    }


# ── GUI ─────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Comparador de Archivos")
        self.geometry("1100x780")
        self.configure(bg="#1e1e2e")
        self.resizable(True, True)

        self.file1_path = tk.StringVar()
        self.file2_path = tk.StringVar()

        self._build_ui()

    # ── layout ──────────────────────────────────────────────────
    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        BG = "#1e1e2e"
        FG = "#cdd6f4"
        ACCENT = "#89b4fa"
        SURFACE = "#313244"
        BTN_BG = "#45475a"

        style.configure(".", background=BG, foreground=FG, fieldbackground=SURFACE)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 13, "bold"), foreground=ACCENT)
        style.configure("TButton", background=BTN_BG, foreground=FG,
                         font=("Segoe UI", 10), padding=6)
        style.map("TButton",
                  background=[("active", ACCENT)],
                  foreground=[("active", "#1e1e2e")])
        style.configure("TEntry", fieldbackground=SURFACE, foreground=FG,
                         insertcolor=FG, font=("Segoe UI", 10))
        style.configure("Accent.TButton", background=ACCENT, foreground="#1e1e2e",
                         font=("Segoe UI", 11, "bold"), padding=8)
        style.map("Accent.TButton",
                  background=[("active", "#b4d0fb")])

        # top frame - file selectors
        top = ttk.Frame(self)
        top.pack(fill="x", padx=16, pady=(16, 8))

        for idx, (var, label) in enumerate([
            (self.file1_path, "Archivo 1:"),
            (self.file2_path, "Archivo 2:"),
        ]):
            row = ttk.Frame(top)
            row.pack(fill="x", pady=4)
            ttk.Label(row, text=label, width=10).pack(side="left")
            entry = ttk.Entry(row, textvariable=var)
            entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
            ttk.Button(row, text="Examinar...",
                       command=lambda v=var: self._browse(v)).pack(side="left")

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text="  Comparar  ", style="Accent.TButton",
                   command=self._compare).pack()

        # results area
        self.result_text = tk.Text(
            self, wrap="word", font=("Cascadia Code", 10),
            bg="#181825", fg=FG, insertbackground=FG,
            selectbackground=ACCENT, selectforeground="#1e1e2e",
            borderwidth=0, padx=12, pady=12,
        )
        self.result_text.pack(fill="both", expand=True, padx=16, pady=(4, 16))

        scroll = ttk.Scrollbar(self.result_text, command=self.result_text.yview)
        scroll.pack(side="right", fill="y")
        self.result_text.configure(yscrollcommand=scroll.set)

        # tags for formatting
        self.result_text.tag_configure("title", font=("Cascadia Code", 12, "bold"),
                                        foreground=ACCENT)
        self.result_text.tag_configure("section", font=("Cascadia Code", 10, "bold"),
                                        foreground="#a6e3a1")
        self.result_text.tag_configure("warn", foreground="#f38ba8")
        self.result_text.tag_configure("ok", foreground="#a6e3a1")
        self.result_text.tag_configure("diff", foreground="#fab387")
        self.result_text.tag_configure("info", foreground="#94e2d5")

    def _browse(self, var: tk.StringVar):
        path = filedialog.askopenfilename(
            title="Seleccionar archivo",
            filetypes=[("Todos los archivos", "*.*"),
                       ("Archivos de texto", "*.txt;*.csv;*.log;*.xml;*.json;*.html;*.css;*.js")]
        )
        if path:
            var.set(path)

    # ── comparison logic ────────────────────────────────────────
    def _compare(self):
        p1, p2 = self.file1_path.get().strip(), self.file2_path.get().strip()
        if not p1 or not p2:
            messagebox.showwarning("Faltan archivos", "Selecciona ambos archivos.")
            return
        if not os.path.isfile(p1) or not os.path.isfile(p2):
            messagebox.showerror("Error", "Uno o ambos archivos no existen.")
            return

        ext1 = os.path.splitext(p1)[1].lower()
        ext2 = os.path.splitext(p2)[1].lower()
        if ext1 != ext2:
            if not messagebox.askyesno(
                "Extensiones distintas",
                f"Las extensiones son diferentes ({ext1} vs {ext2}).\n"
                "Se recomienda comparar archivos de la misma extension.\n\n"
                "Continuar de todos modos?"
            ):
                return

        try:
            a1 = analyze_file(p1)
            a2 = analyze_file(p2)
        except Exception as e:
            messagebox.showerror("Error al leer", str(e))
            return

        self._show_results(a1, a2)

    def _show_results(self, a1: dict, a2: dict):
        txt = self.result_text
        txt.configure(state="normal")
        txt.delete("1.0", "end")

        def title(s):
            txt.insert("end", f"\n{s}\n", "title")
            txt.insert("end", "=" * 70 + "\n")

        def section(s):
            txt.insert("end", f"\n  {s}\n", "section")
            txt.insert("end", "  " + "-" * 50 + "\n")

        def row(label, v1, v2, compare=True):
            tag = ""
            if compare and str(v1) != str(v2):
                tag = "diff"
            prefix = "  != " if tag == "diff" else "     "
            line = f"{prefix}{label:<22}  |  {str(v1):<28}  |  {str(v2)}\n"
            txt.insert("end", line, tag if tag else "info")

        def match_label(v1, v2):
            if str(v1) == str(v2):
                txt.insert("end", "  >> IGUALES\n", "ok")
            else:
                txt.insert("end", "  >> DIFERENTES\n", "warn")

        n1, n2 = a1["nombre"], a2["nombre"]

        # header
        title("COMPARACION DE ARCHIVOS")
        txt.insert("end", f"  Archivo 1:  {a1['ruta']}\n", "info")
        txt.insert("end", f"  Archivo 2:  {a2['ruta']}\n", "info")

        # ── general info ────────────────────────────────────────
        title("INFORMACION GENERAL")
        row("Nombre", n1, n2, compare=False)
        row("Tamano (bytes)", a1["tamano_bytes"], a2["tamano_bytes"])
        row("Num. lineas", a1["num_lineas"], a2["num_lineas"])

        # ── encoding ────────────────────────────────────────────
        title("ENCODING")
        e1, e2 = a1["encoding"], a2["encoding"]
        row("Encoding detectado", e1["encoding"], e2["encoding"])
        match_label(e1["encoding"], e2["encoding"])
        row("Confianza", e1["confianza"], e2["confianza"])
        row("Idioma detectado", e1["idioma"], e2["idioma"])

        # ── BOM ─────────────────────────────────────────────────
        title("BOM (Byte Order Mark)")
        row("BOM", a1["bom"], a2["bom"])
        match_label(a1["bom"], a2["bom"])

        bom1_hex = a1["raw"][:4].hex(" ")
        bom2_hex = a2["raw"][:4].hex(" ")
        row("Primeros 4 bytes (hex)", bom1_hex, bom2_hex)

        # ── line endings ────────────────────────────────────────
        title("LINE ENDINGS (Finales de linea)")
        le1, le2 = a1["line_endings"], a2["line_endings"]
        for key in le1:
            row(key, le1[key], le2[key])

        def dominant(le):
            m = max(le, key=le.get)
            return m if le[m] > 0 else "Ninguno"
        d1, d2 = dominant(le1), dominant(le2)
        row("Predominante", d1, d2)
        match_label(d1, d2)

        mixed1 = sum(1 for v in le1.values() if v > 0) > 1
        mixed2 = sum(1 for v in le2.values() if v > 0) > 1
        if mixed1:
            txt.insert("end", f"  !! Archivo 1 tiene MEZCLA de line endings\n", "warn")
        if mixed2:
            txt.insert("end", f"  !! Archivo 2 tiene MEZCLA de line endings\n", "warn")

        # ── hashes ──────────────────────────────────────────────
        title("HASHES (Integridad)")
        h1, h2 = a1["hashes"], a2["hashes"]
        for alg in h1:
            row(alg, h1[alg], h2[alg])

        if h1["SHA-256"] == h2["SHA-256"]:
            txt.insert("end", "\n  >> Los archivos son IDENTICOS (byte a byte)\n", "ok")
        else:
            txt.insert("end", "\n  >> Los archivos son DIFERENTES en contenido\n", "warn")

        # ── non-printable chars ─────────────────────────────────
        title("CARACTERES NO IMPRIMIBLES / OCULTOS")
        for label, analysis in [("Archivo 1", a1), ("Archivo 2", a2)]:
            np_list = analysis["no_imprimibles"]
            section(f"{label}: {analysis['nombre']}  ({len(np_list)} encontrados)")
            if np_list:
                for pos, cp, name, cat in np_list[:30]:
                    txt.insert("end",
                               f"    pos {pos:>6}  U+{cp:04X}  cat={cat}  {name}\n", "warn")
                if len(np_list) > 30:
                    txt.insert("end", f"    ... y {len(np_list)-30} mas\n", "warn")
            else:
                txt.insert("end", "    Ninguno encontrado\n", "ok")

        # ── homoglyphs ──────────────────────────────────────────
        title("HOMOGLIFOS (Caracteres similares a ASCII pero Unicode)")
        for label, analysis in [("Archivo 1", a1), ("Archivo 2", a2)]:
            hg_list = analysis["homoglifos"]
            section(f"{label}: {analysis['nombre']}  ({len(hg_list)} encontrados)")
            if hg_list:
                for pos, ch, cp, name in hg_list[:30]:
                    txt.insert("end",
                               f"    pos {pos:>6}  '{ch}'  U+{cp:04X}  {name}\n", "diff")
                if len(hg_list) > 30:
                    txt.insert("end", f"    ... y {len(hg_list)-30} mas\n", "diff")
            else:
                txt.insert("end", "    Ninguno encontrado\n", "ok")

        # ── byte distribution diff ──────────────────────────────
        title("DIFERENCIAS EN DISTRIBUCION DE BYTES")
        bf1, bf2 = a1["byte_freq"], a2["byte_freq"]
        all_bytes = sorted(set(bf1.keys()) | set(bf2.keys()))

        diffs = []
        for b in all_bytes:
            c1, c2 = bf1.get(b, 0), bf2.get(b, 0)
            if c1 != c2:
                diffs.append((b, c1, c2))

        if not diffs:
            txt.insert("end", "  Distribucion de bytes identica\n", "ok")
        else:
            txt.insert("end", f"  {len(diffs)} valores de byte difieren:\n\n", "info")
            txt.insert("end", f"  {'Byte':<8} {'Hex':<6} {'Repr':<8} {'Arch.1':>8} {'Arch.2':>8}  {'Diff':>8}\n", "section")
            shown = 0
            for b, c1, c2 in sorted(diffs, key=lambda x: abs(x[2]-x[1]), reverse=True):
                if shown >= 40:
                    txt.insert("end", f"  ... y {len(diffs)-40} mas\n", "info")
                    break
                rep = repr(chr(b)) if 32 <= b < 127 else f"0x{b:02X}"
                txt.insert("end",
                           f"  {b:<8} 0x{b:02X}   {rep:<8} {c1:>8} {c2:>8}  {c2-c1:>+8}\n", "diff")
                shown += 1

        # ── first byte difference ───────────────────────────────
        title("PRIMERA DIFERENCIA BYTE A BYTE")
        r1, r2 = a1["raw"], a2["raw"]
        min_len = min(len(r1), len(r2))
        first_diff = None
        for i in range(min_len):
            if r1[i] != r2[i]:
                first_diff = i
                break

        if first_diff is None and len(r1) == len(r2):
            txt.insert("end", "  No hay diferencias, archivos identicos\n", "ok")
        elif first_diff is None:
            txt.insert("end", f"  Contenido comun identico, pero difieren en tamano "
                              f"({len(r1)} vs {len(r2)} bytes)\n", "warn")
        else:
            txt.insert("end", f"  Primera diferencia en byte offset {first_diff}:\n", "warn")
            # Show context around the difference
            start = max(0, first_diff - 8)
            end = min(min_len, first_diff + 9)
            ctx1 = r1[start:end]
            ctx2 = r2[start:end]
            txt.insert("end", f"    Arch.1: {ctx1.hex(' ')}  |  {repr(ctx1)}\n", "info")
            txt.insert("end", f"    Arch.2: {ctx2.hex(' ')}  |  {repr(ctx2)}\n", "info")
            txt.insert("end", f"    Byte arch.1: 0x{r1[first_diff]:02X} ({r1[first_diff]})\n", "diff")
            txt.insert("end", f"    Byte arch.2: 0x{r2[first_diff]:02X} ({r2[first_diff]})\n", "diff")

        # ── summary ─────────────────────────────────────────────
        title("RESUMEN")
        issues = []
        enc1 = a1["encoding"]["encoding"]
        enc2 = a2["encoding"]["encoding"]
        if enc1 != enc2:
            issues.append(f"Encoding diferente: {enc1} vs {enc2}")
        if a1["bom"] != a2["bom"]:
            issues.append(f"BOM diferente: {a1['bom']} vs {a2['bom']}")
        if d1 != d2:
            issues.append(f"Line endings diferentes: {d1} vs {d2}")
        if mixed1 or mixed2:
            which = []
            if mixed1: which.append("Archivo 1")
            if mixed2: which.append("Archivo 2")
            issues.append(f"Line endings mezclados en: {', '.join(which)}")
        if a1["no_imprimibles"] or a2["no_imprimibles"]:
            issues.append(f"Caracteres ocultos: {len(a1['no_imprimibles'])} en Arch.1, "
                          f"{len(a2['no_imprimibles'])} en Arch.2")
        if a1["homoglifos"] or a2["homoglifos"]:
            issues.append(f"Homoglifos: {len(a1['homoglifos'])} en Arch.1, "
                          f"{len(a2['homoglifos'])} en Arch.2")
        if a1["tamano_bytes"] != a2["tamano_bytes"]:
            issues.append(f"Tamano diferente: {a1['tamano_bytes']} vs {a2['tamano_bytes']} bytes")

        if not issues:
            txt.insert("end", "  No se encontraron diferencias significativas.\n", "ok")
        else:
            txt.insert("end", f"  Se encontraron {len(issues)} diferencia(s):\n\n", "warn")
            for i, issue in enumerate(issues, 1):
                txt.insert("end", f"    {i}. {issue}\n", "warn")

        txt.insert("end", "\n")
        txt.configure(state="disabled")


if __name__ == "__main__":
    app = App()
    app.mainloop()
