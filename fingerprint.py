#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fingerprint.py
==============
Módulo reutilizável para tokenização tolerante e fingerprint estrutural.
Substitui duplicação anterior entre advanced_analysis.py e outros consumidores.

Objetivos:
 - Tokenizer tolerante (uma passada, regex compilada once)
 - StructuralFingerprint dataclass com várias métricas úteis
 - compute_fingerprint(src) -> StructuralFingerprint
 - Pequenas otimizações e tipos para facilitar reuso
"""

from __future__ import annotations

import re
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional

# Tokenizer: compilado uma única vez (uso global, rápido)
_TOKEN_RE = re.compile(
    r"""
    (?P<LONGCOMMENT>--\[(?P<eq1>=*)\[.*?\](?P=eq1)\])            # long comment --[[ ... ]]
  | (?P<COMMENT>--[^\n]*)                                       # single-line comment
  | (?P<LONGSTRING>\[(?P<eq2>=*)\[.*?\](?P=eq2)\])              # long string [[ ... ]]
  | (?P<STRING>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')         # short strings
  | (?P<NUMBER>0[xX][0-9a-fA-F_]+(?:\.[0-9a-fA-F_]*)?(?:[pP][+-]?\d+)?|0[bB][01_]+|\d[\d_]*\.?[\d_]*(?:[eE][+-]?\d+)?)  # numbers (hex/bin/dec)
  | (?P<IDENT>[A-Za-z_][A-Za-z0-9_]*)                           # identifiers
  | (?P<OP>\.\.\.|\.\.|==|~=|<=|>=|::|[{}()\[\]:;,.+\-*/%^#<>=&|~])  # operators & punctuation
    """,
    re.DOTALL | re.VERBOSE,
)

_LUA_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return",
    "then", "true", "until", "while",
}

_BLOCK_OPEN = {"function", "do", "then", "repeat"}
_BLOCK_CLOSE = {"end", "until"}


@dataclass
class Token:
    kind: str
    text: str
    pos: int


def tokenize(src: str) -> List[Token]:
    """Tokeniza o código em uma única passada, retornando apenas tokens relevantes.
    Tolerante a variações de dialecto (não é um parser).
    """
    tokens: List[Token] = []
    for m in _TOKEN_RE.finditer(src):
        kind = m.lastgroup
        if kind in ("LONGCOMMENT", "COMMENT", "LONGSTRING", "STRING", "NUMBER", "IDENT", "OP"):
            tokens.append(Token(kind, m.group(), m.start()))
    return tokens


@dataclass
class StructuralFingerprint:
    num_functions: int = 0
    num_closures: int = 0
    num_tables: int = 0
    num_strings: int = 0
    num_numbers: int = 0
    num_constants: int = 0
    num_operators: int = 0
    max_block_depth: int = 0
    avg_identifier_len: float = 0.0
    longest_identifier: str = ""
    unique_identifiers: int = 0
    density_functions_per_kb: float = 0.0
    density_tables_per_kb: float = 0.0
    density_strings_per_kb: float = 0.0
    density_numbers_per_kb: float = 0.0
    avg_line_len: float = 0.0
    max_line_len: int = 0
    min_line_len: int = 0
    pct_blank_lines: float = 0.0
    num_comments: int = 0
    num_long_comments: int = 0
    keyword_usage: Dict[str, int] = field(default_factory=dict)
    entropy: float = 0.0
    char_distribution: Dict[str, int] = field(default_factory=dict)
    operator_distribution: Dict[str, int] = field(default_factory=dict)

    def summary_lines(self) -> List[str]:
        lines = [
            f"Funções: {self.num_functions}  |  Closures (aninhadas): {self.num_closures}  |  Tabelas: {self.num_tables}",
            f"Strings: {self.num_strings}  |  Números: {self.num_numbers}  |  Operadores: {self.num_operators}",
            f"Profundidade máxima de blocos: {self.max_block_depth}",
            f"Identificadores únicos: {self.unique_identifiers}  |  Tamanho médio: {self.avg_identifier_len:.1f}  |  Maior: '{self.longest_identifier[:30]}'",
            f"Densidade (por KB): funções {self.density_functions_per_kb:.2f} | tabelas {self.density_tables_per_kb:.2f} | strings {self.density_strings_per_kb:.2f} | números {self.density_numbers_per_kb:.2f}",
            f"Linhas: média {self.avg_line_len:.1f} chars | maior {self.max_line_len} | menor {self.min_line_len} | {self.pct_blank_lines:.1f}% em branco",
            f"Comentários: {self.num_comments} (longos: {self.num_long_comments})",
            f"Entropia do arquivo: {self.entropy:.3f}",
        ]
        return lines


# Padrões de API/palavra-chave úteis para fingerprint (pré compilado para performance)
_KEYWORD_API_PATTERNS = {
    "goto": r"\bgoto\s+\w+\b",
    "while_true": r"\bwhile\s+true\s+do\b",
    "repeat_until": r"\brepeat\b",
    "for_numeric": r"\bfor\s+\w+\s*=\s*[^,]+,",
    "for_generic": r"\bfor\s+[\w,\s]+\s+in\s+",
    "ipairs": r"\bipairs\s*\(",
    "pairs": r"\bpairs\s*\(",
    "unpack": r"\bunpack\s*\(",
    "select": r"\bselect\s*\(",
    "coroutine": r"\bcoroutine\.",
    "debug": r"\bdebug\.",
    "getfenv": r"\bgetfenv\s*\(",
    "setfenv": r"\bsetfenv\s*\(",
    "load": r"(?<![a-zA-Z_])load\s*\(",
    "loadstring": r"\bloadstring\s*\(",
    "string_dump": r"\bstring\.dump\s*\(",
    "string_byte": r"\bstring\.byte\s*\(",
    "string_char": r"\bstring\.char\s*\(",
    "table_concat": r"\btable\.concat\s*\(",
    "table_insert": r"\btable\.insert\s*\(",
    "table_remove": r"\btable\.remove\s*\(",
    "bit32": r"\bbit32\.",
    "bit_lib": r"(?<!\w)bit\.",
    "xor_word": r"\bxor\b",
    "bxor": r"\bbxor\b",
    "lshift": r"\blshift\b",
    "rshift": r"\brshift\b",
}
_KEYWORD_API_COMPILED = {k: re.compile(v, re.IGNORECASE) for k, v in _KEYWORD_API_PATTERNS.items()}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def compute_fingerprint(src: str, tokens: Optional[List[Token]] = None) -> StructuralFingerprint:
    """Compute a structural fingerprint for a Lua source text.

    Tokenizes once (if tokens omitted), then aggregates a set of robust metrics.
    """
    if tokens is None:
        tokens = tokenize(src)

    fp = StructuralFingerprint()
    lines = src.splitlines()
    size_kb = max(len(src) / 1024.0, 0.001)

    depth = 0
    max_depth = 0
    ident_counter = Counter()
    ident_lengths = []
    longest = ""

    operator_counter = Counter()
    char_counter = Counter(src)

    prev_kind = None
    for t in tokens:
        if t.kind == "IDENT":
            if t.text == "function":
                fp.num_functions += 1
                if depth > 0:
                    fp.num_closures += 1
                depth += 1
                max_depth = max(max_depth, depth)
            elif t.text in _BLOCK_OPEN:
                depth += 1
                max_depth = max(max_depth, depth)
            elif t.text in _BLOCK_CLOSE:
                depth = max(0, depth - 1)
            elif t.text not in _LUA_KEYWORDS:
                ident_counter[t.text] += 1
                ident_lengths.append(len(t.text))
                if len(t.text) > len(longest):
                    longest = t.text
        elif t.kind in ("STRING", "LONGSTRING"):
            fp.num_strings += 1
            fp.num_constants += 1
        elif t.kind == "NUMBER":
            fp.num_numbers += 1
            fp.num_constants += 1
        elif t.kind == "OP":
            fp.num_operators += 1
            operator_counter[t.text] += 1
            if t.text == "{":
                fp.num_tables += 1
        elif t.kind in ("COMMENT", "LONGCOMMENT"):
            fp.num_comments += 1
            if len(t.text) > 40:
                fp.num_long_comments += 1
        prev_kind = t.kind

    fp.max_block_depth = max_depth
    fp.unique_identifiers = len(ident_counter)
    fp.avg_identifier_len = (sum(ident_lengths) / len(ident_lengths)) if ident_lengths else 0.0
    fp.longest_identifier = longest

    fp.density_functions_per_kb = fp.num_functions / size_kb
    fp.density_tables_per_kb = fp.num_tables / size_kb
    fp.density_strings_per_kb = fp.num_strings / size_kb
    fp.density_numbers_per_kb = fp.num_numbers / size_kb

    if lines:
        lens = [len(l) for l in lines]
        fp.avg_line_len = sum(lens) / len(lens)
        fp.max_line_len = max(lens)
        fp.min_line_len = min(lens)
        fp.pct_blank_lines = 100.0 * sum(1 for l in lines if not l.strip()) / len(lines)

    fp.keyword_usage = {name: len(pat.findall(src)) for name, pat in _KEYWORD_API_COMPILED.items()}
    fp.entropy = shannon_entropy(src)
    fp.char_distribution = dict(char_counter)
    fp.operator_distribution = dict(operator_counter)

    return fp
