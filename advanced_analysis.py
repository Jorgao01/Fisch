#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
advanced_analysis.py
=====================

Módulo ADITIVO para análise avançada (opção --advanced). Não altera o veredito
padrão quando não usado.

Refatorações principais:
 - Reutiliza fingerprint.compute_fingerprint (novo módulo fingerprint.py)
 - Mantém heurísticas / scores originais, com tipagem e pequenos ajustes.
"""

from __future__ import annotations

import re
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional

# Importa fingerprint centralizado (tokenizer + compute_fingerprint)
from fingerprint import compute_fingerprint, StructuralFingerprint, tokenize

# --------------------------------------------------------------------------
# Técnicas específicas (encoding / cifra / compressão)
# --------------------------------------------------------------------------

_TECHNIQUE_PATTERNS = {
    "Base64": re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'),
    "Base32": re.compile(r'["\']([A-Z2-7]{40,}=*)["\']'),
    "Base58": re.compile(r'["\']([1-9A-HJ-NP-Za-km-z]{40,})["\']'),
    "Base85": re.compile(r'["\']([!-u]{40,})["\']'),
    "Hex_escapes": re.compile(r'\\x[0-9a-fA-F]{2}'),
    "Hex_literals": re.compile(r'\b0[xX][0-9a-fA-F_]{2,}\b'),
    "Binary_literals": re.compile(r'\b0[bB][01_]{4,}\b'),
    "Octal_escapes": re.compile(r'\\(?:[0-7]{1,3})'),
    "Decimal_escapes": re.compile(r'\\\d{1,3}'),
    "Unicode_escapes": re.compile(r'\\u\{[0-9a-fA-F]+\}'),
    "XOR_ops": re.compile(r'bit32\s*\.\s*bxor|bit\s*\.\s*bxor|\bbxor\b|\bxor\b', re.IGNORECASE),
    "RC4_like": re.compile(r'for\s+\w+\s*=\s*0\s*,\s*255\s+do'),
    "TEA_XXTEA_delta": re.compile(r'0x9E3779B9|2654435769', re.IGNORECASE),
    "AES_sbox": re.compile(r'0x63\s*,\s*0x7[cC]\s*,\s*0x77\s*,\s*0x7[bB]|99\s*,\s*124\s*,\s*119\s*,\s*123'),
    "gzip_magic": re.compile(r'\\31\\139|\\x1[fF]\\x8[bB]'),
    "zlib_magic": re.compile(r'\\120\\156|\\120\\1\b|\\120\\218|\\x78\\x9[cC]|\\x78\\x01|\\x78\\x[dD][aA]'),
    "compression_names": re.compile(r'\b(?:gzip|zlib|inflate|deflate|lzw|lz4|huffman)\b', re.IGNORECASE),
}


def detect_techniques(src: str) -> Dict[str, Tuple[int, int]]:
    """Retorna {tecnica: (contagem, posicao_primeira_ocorrencia_ou_-1)}."""
    out: Dict[str, Tuple[int, int]] = {}
    for name, pat in _TECHNIQUE_PATTERNS.items():
        matches = list(pat.finditer(src))
        if matches:
            out[name] = (len(matches), matches[0].start())
    return out


def probable_layer_chain(techniques: Dict[str, Tuple[int, int]]) -> List[str]:
    """Ordena as técnicas detectadas pela posição da primeira ocorrência no arquivo."""
    ordered = sorted(techniques.items(), key=lambda kv: kv[1][1])
    return [name for name, _ in ordered]


# --------------------------------------------------------------------------
# Scores por categoria (0-100, cada um com evidências)
# --------------------------------------------------------------------------

def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


def category_scores(src: str, fp: StructuralFingerprint, techniques: Dict[str, Tuple[int, int]]) -> Dict[str, Tuple[float, List[str]]]:
    kw = fp.keyword_usage
    scores: Dict[str, Tuple[float, List[str]]] = {}

    # --- Virtual Machine ---
    opcode_table = len(re.findall(r'\[\s*\d+\s*\]\s*=\s*function', src))
    elseif_ladder = len(re.findall(r'elseif\s+\w+\s*[<>]=?\s*-?\d+\s*then', src))
    dispatch_loop = len(re.findall(r'while\s+\w+\s*(?:~=|==|<|>)\s*-?\d+\s+do', src)) + \
                     len(re.findall(r'until\s+\w+\s*==\s*-?\d+', src))
    register_like = len(set(re.findall(r'\w+\[(0x[0-9A-Fa-f]+)\]', src)))
    memo_jump = len(re.findall(r'\w+\[-?\d+\]\s*or\s+\w+\(', src))
    vm_raw = opcode_table * 3 + elseif_ladder * 1.2 + dispatch_loop * 8 + min(register_like, 30) * 1.5 + memo_jump * 4
    vm_score = _clamp(vm_raw)
    vm_ev: List[str] = []
    if opcode_table: vm_ev.append(f"Tabela de opcodes numerados: {opcode_table}")
    if elseif_ladder: vm_ev.append(f"Ramos de dispatcher em elseif: {elseif_ladder}")
    if dispatch_loop: vm_ev.append(f"Loop(s) de dispatch (while/repeat com variável de estado): {dispatch_loop}")
    if register_like: vm_ev.append(f"Indexação tipo 'registrador virtual' (chaves hex distintas): {register_like}")
    if memo_jump: vm_ev.append(f"Padrão de jump table memoizada (tbl[n] or fn(...)): {memo_jump}")
    scores["Virtual Machine"] = (vm_score, vm_ev)

    # --- String Encryption ---
    xor_n = techniques.get("XOR_ops", (0, 0))[0]
    rc4_n = techniques.get("RC4_like", (0, 0))[0]
    decode_loop = kw.get("string_byte", 0) >= 3 and kw.get("string_char", 0) >= 3
    se_raw = xor_n * 4 + rc4_n * 25 + (15 if decode_loop else 0)
    se_score = _clamp(se_raw)
    se_ev: List[str] = []
    if xor_n: se_ev.append(f"Operações XOR/bxor: {xor_n}")
    if rc4_n: se_ev.append(f"Loop(s) estilo RC4 (for 0,255): {rc4_n}")
    if decode_loop: se_ev.append("Rotina de decodificação byte-a-byte (string.byte + string.char)")
    scores["String Encryption"] = (se_score, se_ev)

    # --- Number Encoding ---
    hex_lit = techniques.get("Hex_literals", (0, 0))[0]
    bin_lit = techniques.get("Binary_literals", (0, 0))[0]
    arith_expr = len(re.findall(r'\(\s*-?\d+\s*[\+\-\*]\s*-?\d+\s*\)\s*[\+\-\*/]\s*-?\d+', src))
    mixed_bases = 1 if (hex_lit >= 10 and bin_lit >= 10) else 0
    ne_raw = min(hex_lit, 100) * 0.3 + min(bin_lit, 100) * 0.5 + arith_expr * 3 + mixed_bases * 20
    ne_score = _clamp(ne_raw)
    ne_ev: List[str] = []
    if hex_lit: ne_ev.append(f"Literais hexadecimais: {hex_lit}")
    if bin_lit: ne_ev.append(f"Literais binários: {bin_lit}")
    if arith_expr: ne_ev.append(f"Expressões aritméticas substituindo constantes: {arith_expr}")
    if mixed_bases: ne_ev.append("Mistura pesada de bases numéricas diferentes no mesmo arquivo")
    scores["Number Encoding"] = (ne_score, ne_ev)

    # --- Control Flow Flattening ---
    goto_n = kw.get("goto", 0)
    while_true_n = kw.get("while_true", 0)
    cff_raw = goto_n * 6 + while_true_n * 10 + elseif_ladder * 1.5 + (fp.max_block_depth * 0.8)
    cff_score = _clamp(cff_raw)
    cff_ev: List[str] = []
    if goto_n: cff_ev.append(f"Uso de goto: {goto_n}")
    if while_true_n: cff_ev.append(f"Loop(s) 'while true do': {while_true_n}")
    if elseif_ladder: cff_ev.append(f"Árvore de elseif profunda: {elseif_ladder} ramos")
    scores["Control Flow Flattening"] = (cff_score, cff_ev)

    # --- Constant Encryption ---
    const_array = len(re.findall(r'local\s+\w+\s*=\s*\{(?:\s*["\'][^"\']{0,40}["\']\s*,){5,}', src))
    ce_raw = const_array * 25 + min(fp.num_strings, 200) * 0.15
    ce_score = _clamp(ce_raw)
    ce_ev: List[str] = []
    if const_array: ce_ev.append(f"Array de constantes de string grande: {const_array}")
    scores["Constant Encryption"] = (ce_score, ce_ev)

    # --- Bytecode ---
    dump_n = kw.get("string_dump", 0)
    load_wrap = len(re.findall(r'assert\s*\(\s*load\s*\(', src)) + len(re.findall(r'\bloadstring\s*\(\s*\w+\s*\(', src))
    bc_raw = dump_n * 30 + load_wrap * 20 + (10 if techniques.get("Hex_literals", (0,0))[0] >= 50 else 0)
    bc_score = _clamp(bc_raw)
    bc_ev: List[str] = []
    if dump_n: bc_ev.append(f"Uso de string.dump: {dump_n}")
    if load_wrap: bc_ev.append(f"load()/loadstring() encapsulando resultado de outra função: {load_wrap}")
    scores["Bytecode"] = (bc_score, bc_ev)

    # --- Compression ---
    gzip_n = techniques.get("gzip_magic", (0, 0))[0]
    zlib_n = techniques.get("zlib_magic", (0, 0))[0]
    comp_name_n = techniques.get("compression_names", (0, 0))[0]
    comp_raw = gzip_n * 60 + zlib_n * 60 + comp_name_n * 10
    comp_score = _clamp(comp_raw)
    comp_ev: List[str] = []
    if gzip_n: comp_ev.append("Magic bytes de gzip (0x1f 0x8b) encontrados em string literal")
    if zlib_n: comp_ev.append("Magic bytes de zlib (0x78 ..) encontrados em string literal")
    if comp_name_n and not (gzip_n or zlib_n):
        comp_ev.append(f"Menção a nome de algoritmo de compressão no código (sinal fraco): {comp_name_n}")
    scores["Compression"] = (comp_score, comp_ev)

    # --- Anti Debug ---
    ad_extra = len(re.findall(
        r'\bgetinfo\b|\btraceback\b|\bhookfunction\b|\bhookmetamethod\b|\bcheckcaller\b|'
        r'\bidentifyexecutor\b|\bislclosure\b|\bisexecutorclosure\b|\bgetgc\b|\bgetrenv\b|\bgetgenv\b',
        src, re.IGNORECASE))
    ad_raw = kw.get("debug", 0) * 8 + ad_extra * 15
    ad_score = _clamp(ad_raw)
    ad_ev: List[str] = []
    if kw.get("debug", 0): ad_ev.append(f"Uso da lib debug.*: {kw['debug']}")
    if ad_extra: ad_ev.append(f"Chamadas típicas de anti-debug/anti-executor: {ad_extra}")
    scores["Anti Debug"] = (ad_score, ad_ev)

    # --- Anti Tamper ---
    hash_loop = len(re.findall(r'\w+\s*=\s*\(\s*\w+\s*\*\s*\d+\s*\+\s*\w+\s*\)\s*%\s*\d+', src))
    self_check = len(re.findall(r'string\.dump\s*\([^)]*\)\s*(?:==|~=)', src))
    at_raw = hash_loop * 20 + self_check * 30
    at_score = _clamp(at_raw)
    at_ev: List[str] = []
    if hash_loop: at_ev.append(f"Loop(s) acumulador tipo hash (h = h*K + byte mod M): {hash_loop}")
    if self_check: at_ev.append(f"Comparação direta do resultado de string.dump: {self_check}")
    scores["Anti Tamper"] = (at_score, at_ev)

    # --- Loader ---
    httpget = len(re.findall(r'HttpGet(?:Async)?\s*\(', src, re.IGNORECASE))
    loadstring_game = len(re.findall(r'loadstring\s*\(\s*game', src))
    getfullname = len(re.findall(r'GetFullName\s*\(\s*\)', src))
    ld_raw = httpget * 25 + loadstring_game * 20 + getfullname * 15
    ld_score = _clamp(ld_raw)
    ld_ev: List[str] = []
    if httpget: ld_ev.append(f"Chamadas HttpGet/HttpGetAsync: {httpget}")
    if loadstring_game: ld_ev.append(f"loadstring(game:...): {loadstring_game}")
    if getfullname: ld_ev.append(f"script:GetFullName() (checagem de licença comum em loaders): {getfullname}")
    scores["Loader"] = (ld_score, ld_ev)

    # --- Environment Spoof ---
    env_spoof = len(re.findall(
        r'\bnewcclosure\b|\bhookfunction\b|\bhookmetamethod\b|\bgetrawmetatable\b|'
        r'\bsetreadonly\b|\bcheckcaller\b|\bidentifyexecutor\b|\bgetgenv\b|\bgetrenv\b',
        src, re.IGNORECASE))
    es_score = _clamp(env_spoof * 12)
    es_ev = [f"Funções de spoof/inspeção de ambiente de executor: {env_spoof}"] if env_spoof else []
    scores["Environment Spoof"] = (es_score, es_ev)

    # --- Dynamic Execution ---
    load_n = kw.get("load", 0) + kw.get("loadstring", 0)
    dyn_build = len(re.findall(r'table\.concat\s*\([^)]*\)\s*\)\s*\(', src))
    de_raw = load_n * 15 + dyn_build * 20
    de_score = _clamp(de_raw)
    de_ev: List[str] = []
    if load_n: de_ev.append(f"Chamadas a load()/loadstring(): {load_n}")
    if dyn_build: de_ev.append(f"String montada dinamicamente (table.concat) e executada: {dyn_build}")
    scores["Dynamic Execution"] = (de_score, de_ev)

    # --- Encoding (agregado) ---
    enc_hits = sum(techniques.get(k, (0, 0))[0] for k in
                   ("Base64", "Base32", "Base58", "Base85", "Hex_escapes", "Octal_escapes",
                    "Decimal_escapes", "Unicode_escapes"))
    enc_score = _clamp(enc_hits * 3)
    enc_ev = [f"{k}: {v[0]}" for k, v in techniques.items() if k in
              ("Base64", "Base32", "Base58", "Base85", "Hex_escapes", "Octal_escapes",
               "Decimal_escapes", "Unicode_escapes")]
    scores["Encoding"] = (enc_score, enc_ev)

    # --- Dead/Junk Code (heurística fraca, propositalmente conservadora) ---
    opaque = len(re.findall(r'\d+\s*%\s*\d+\s*==\s*0|\d+\s*-\s*\d+\s*==\s*0', src))
    always_false = len(re.findall(r'\bif\s+false\s+then\b', src))
    djc_raw = opaque * 5 + always_false * 15
    djc_score = _clamp(djc_raw)
    djc_ev: List[str] = []
    if opaque: djc_ev.append(f"Predicados opacos (tautologias numéricas): {opaque} [sinal fraco]")
    if always_false: djc_ev.append(f"Blocos 'if false then' (código inalcançável óbvio): {always_false}")
    scores["Dead/Junk Code"] = (djc_score, djc_ev)

    return scores


# --------------------------------------------------------------------------
# Família provável sem depender de watermark
# --------------------------------------------------------------------------

def probable_family_no_watermark(basic_results) -> List[Tuple[str, float]]:
    """Recebe a lista de DetectionResult já calculada pelo motor principal
    (lua_obf_detector.analyze_source) e devolve o ranking de confiança
    ESTRUTURAL (sem contar watermark nenhum) das ferramentas tier 1."""
    ranked = sorted(
        (r for r in basic_results if getattr(r, "tier", 2) == 1 and r.structural_max >= 20 and r.structural_hits >= 1),
        key=lambda r: r.structural_confidence,
        reverse=True,
    )
    return [(r.name, r.structural_confidence) for r in ranked if r.structural_confidence > 0][:5]


# --------------------------------------------------------------------------
# Ponto de entrada único
# --------------------------------------------------------------------------

@dataclass
class AdvancedReport:
    fingerprint: StructuralFingerprint
    category_scores: Dict[str, Tuple[float, List[str]]]
    techniques: Dict[str, Tuple[int, int]]
    layer_chain: List[str]
    family_no_watermark: List[Tuple[str, float]]


def run_advanced_analysis(src: str, basic_results=None) -> AdvancedReport:
    # Reutiliza compute_fingerprint do módulo fingerprint (tokeniza internamente)
    fp = compute_fingerprint(src)
    techniques = detect_techniques(src)
    cats = category_scores(src, fp, techniques)
    chain = probable_layer_chain(techniques)
    family = probable_family_no_watermark(basic_results) if basic_results is not None else []
    return AdvancedReport(fp, cats, techniques, chain, family)


def format_advanced_report(report: AdvancedReport) -> str:
    lines = ["", "  --- Análise avançada ---", "  Fingerprint estrutural:"]
    for l in report.fingerprint.summary_lines():
        lines.append(f"    {l}")

    lines.append("  Scores por categoria (0-100):")
    for name, (score, ev) in sorted(report.category_scores.items(), key=lambda kv: kv[1][0], reverse=True):
        if score <= 0:
            continue
        bar = "█" * int(score // 5)
        lines.append(f"    {name:<24} {score:5.1f}  {bar}")
        for e in ev:
            lines.append(f"        - {e}")

    if report.techniques:
        lines.append("  Técnicas específicas detectadas:")
        for name, (count, _) in sorted(report.techniques.items(), key=lambda kv: -kv[1][0]):
            lines.append(f"    - {name}: {count}")

    if report.layer_chain:
        lines.append("  Cadeia provável de camadas (por ordem de aparição -- heurística posicional):")
        lines.append("    " + " -> ".join(report.layer_chain))

    if report.family_no_watermark:
        lines.append("  Família provável baseada só em estrutura (ignorando watermark):")
        for name, conf in report.family_no_watermark:
            lines.append(f"    - {name}: {conf:.1f}%")

    return "\n".join(lines)
