#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lua/Roblox Obfuscation Detector v3
====================================

(arquivo levemente refatorado para pré-compilar regexes das assinaturas e
melhorar performance/reuso; API e comportamento públicos preservados)
"""

import sys
import os
import re
import math
import json
import argparse
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional

# Configure logger for warnings about signatures/regex
_logger = logging.getLogger(__name__)
if not _logger.handlers:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.WARNING)

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures.json")


# --------------------------------------------------------------------------
# Utilidades gerais
# --------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def re_flags(flag_str: str) -> int:
    flags = 0
    for ch in (flag_str or ""):
        if ch == "i":
            flags |= re.IGNORECASE
        elif ch == "m":
            flags |= re.MULTILINE
        elif ch == "s":
            flags |= re.DOTALL
    return flags


@dataclass
class DetectionResult:
    name: str
    tier: int
    score: int = 0
    max_score: int = 0
    explicit: bool = False
    evidences: List[str] = field(default_factory=list)
    structural_score: int = 0
    structural_max: int = 0
    structural_hits: int = 0
    version: Optional[str] = None

    def add(self, points: int, reason: str, explicit: bool = False):
        self.score += points
        self.evidences.append(reason)
        if explicit:
            self.explicit = True
        else:
            self.structural_score += points
            self.structural_hits += 1

    @property
    def confidence(self) -> float:
        if self.max_score == 0:
            return 0.0
        return max(0.0, min(100.0, (self.score / self.max_score) * 100))

    @property
    def structural_confidence(self) -> float:
        if self.structural_max == 0:
            return 0.0
        return max(0.0, min(100.0, (self.structural_score / self.structural_max) * 100))

    @property
    def display_name(self) -> str:
        return f"{self.name} (v{self.version})" if self.version else self.name


# --------------------------------------------------------------------------
# Engine orientado a dados (lê signatures.json) - com pré-compilação de regex
# --------------------------------------------------------------------------

def load_rules(path: str) -> Dict[str, Any]:
    """Carrega signatures.json e pré-compila padrões regex para uso repetido.

    Mantemos o dict original (para compatibilidade com formatos esperados),
    mas adicionamos chaves '_compiled' (ou '_compiled_list') dentro de cada
    check para acelerar as buscas posteriores.
    """
    with open(path, "r", encoding="utf-8") as f:
        rules = json.load(f)

    # Pré-compile regexes nas checagens
    for tool in rules.get("tools", []):
        for check in tool.get("checks", []):
            ctype = check.get("type", "regex")
            flags = re_flags(check.get("flags", ""))
            if ctype == "regex":
                pattern = check.get("pattern")
                if pattern:
                    try:
                        check["_compiled"] = re.compile(pattern, flags)
                    except re.error as e:
                        _logger.warning(f"Regex inválida em tool '{tool.get('name')}' ignorada: {e} -> {pattern}")
                        check["_compiled"] = None
            elif ctype == "regex_all":
                patterns = check.get("patterns", [])
                compiled = []
                for p in patterns:
                    try:
                        compiled.append(re.compile(p, flags))
                    except re.error as e:
                        _logger.warning(f"Regex inválida em tool '{tool.get('name')}' (regex_all) ignorada: {e} -> {p}")
                        compiled.append(None)
                check["_compiled_list"] = compiled
            # long_lines / short_high_entropy não precisam de compilação
    return rules


def run_check(check: Dict[str, Any], src: str, lines: List[str], entropy: float) -> Tuple[bool, int]:
    """Roda um check individual. Usa padrões pré-compilados quando disponíveis.
    Retorna (bateu, contagem_representativa).
    """
    ctype = check.get("type", "regex")
    if ctype == "regex":
        pat = check.get("_compiled")
        if pat is None and check.get("pattern"):
            # fallback: compile on the fly (defensivo)
            try:
                pat = re.compile(check["pattern"], re_flags(check.get("flags", "")))
            except re.error:
                return False, 0
        try:
            n = len(pat.findall(src)) if pat else 0
            return n >= check.get("min_count", 1), n
        except Exception:
            return False, 0

    if ctype == "regex_all":
        compiled = check.get("_compiled_list")
        patterns = check.get("patterns", [])
        min_counts = check.get("min_counts", [1] * len(patterns))
        counts = []
        # iterate compiled patterns; if any is None, attempt compile on the fly
        for i, p in enumerate(patterns):
            pat = None
            if compiled and i < len(compiled):
                pat = compiled[i]
            if pat is None:
                try:
                    pat = re.compile(p, re_flags(check.get("flags", "")))
                except re.error:
                    counts.append(0)
                    continue
            try:
                counts.append(len(pat.findall(src)))
            except Exception:
                counts.append(0)
        ok = all(c >= m for c, m in zip(counts, min_counts))
        return ok, min(counts) if counts else 0

    if ctype == "long_lines":
        threshold = check.get("threshold", 3000)
        n = sum(1 for l in lines if len(l) > threshold)
        return n >= check.get("min_count", 1), n

    if ctype == "short_high_entropy":
        max_lines = check.get("max_lines", 30)
        min_entropy = check.get("min_entropy", 4.5)
        ok = len(lines) <= max_lines and entropy > min_entropy
        return ok, len(lines)

    _logger.warning(f"tipo de check desconhecido ignorado: {ctype}")
    return False, 0


def analyze_source(src: str, rules: Dict[str, Any]) -> List[DetectionResult]:
    lines = src.splitlines()
    entropy = shannon_entropy(src)

    results: List[DetectionResult] = []
    for tool in rules.get("tools", []):
        r = DetectionResult(tool["name"], tier=tool.get("tier", 1), max_score=tool.get("max_score", 100))
        r.structural_max = sum(c.get("points", 0) for c in tool.get("checks", []) if not c.get("explicit"))
        for check in tool.get("checks", []):
            ok, count = run_check(check, src, lines, entropy)
            if ok:
                reason = check.get("reason", "").replace("{count}", str(count))
                r.add(check.get("points", 0), reason, explicit=check.get("explicit", False))

        version_pattern = tool.get("version_pattern")
        if version_pattern:
            try:
                m = re.search(version_pattern, src, re.IGNORECASE)
                if m and m.groups():
                    r.version = m.group(1)
            except re.error:
                # Não falhar por causa de regex de versão malformada
                pass

        results.append(r)
    return results


# --------------------------------------------------------------------------
# Lógica de escolha de vencedor (sem alterações comportamentais, apenas leve
# reorganização estética)
# --------------------------------------------------------------------------

TIER1_MIN_CONFIDENCE = 25
TIER2_MIN_CONFIDENCE = 25
CONFLICT_MIN_STRUCTURAL = 35   # confiança estrutural mínima do "outro" candidato pra sequer considerar conflito
CONFLICT_MARGIN = 20          # o "outro" candidato precisa superar o vencedor por watermark por essa margem


def pick_winner(results: List[DetectionResult]) -> DetectionResult:
    explicit_hits = [r for r in results if r.explicit]
    if explicit_hits:
        winner = max(explicit_hits, key=lambda r: (r.confidence, len(r.evidences)))

        candidates = [
            r for r in results
            if r is not winner and r.tier == 1
            and r.structural_max >= 40
            and r.structural_hits >= 2
        ]
        best_other = max(candidates, key=lambda r: r.structural_confidence, default=None)

        if (best_other is not None
                and best_other.structural_confidence >= CONFLICT_MIN_STRUCTURAL
                and best_other.structural_confidence > winner.structural_confidence + CONFLICT_MARGIN):
            note = (
                f"[CONFLITO] O watermark do arquivo afirma ser '{winner.name}', mas a estrutura do código "
                f"bate muito mais com '{best_other.name}' ({best_other.structural_confidence:.0f}% de "
                f"confiança estrutural, contra {winner.structural_confidence:.0f}% de '{winner.name}'). "
                f"O comentário de watermark pode ter sido editado manualmente, copiado, ou este pode ser "
                f"um obfuscador que reaproveita/faz rebrand da saída de outro."
            )
            best_other.evidences = best_other.evidences + [note]
            resolved_score = min(75.0, max(50.0, best_other.structural_confidence))
            best_other.score = int(best_other.max_score * resolved_score / 100)
            return best_other

        winner_score = min(99.0, max(85.0, winner.confidence))
        winner.score = int(winner.max_score * winner_score / 100)
        return winner

    tier1 = sorted([r for r in results if r.tier == 1], key=lambda r: (r.confidence, len(r.evidences)), reverse=True)
    if tier1 and tier1[0].confidence >= TIER1_MIN_CONFIDENCE:
        return tier1[0]

    tier2 = sorted([r for r in results if r.tier == 2], key=lambda r: (r.confidence, len(r.evidences)), reverse=True)
    if tier2 and tier2[0].confidence >= TIER2_MIN_CONFIDENCE:
        return tier2[0]

    everything = sorted(results, key=lambda r: r.confidence, reverse=True)
    return everything[0] if everything else DetectionResult("Desconhecido", tier=2, max_score=1)


# --------------------------------------------------------------------------
# Arquivo/análise e formatação (sem alterações de API)
# --------------------------------------------------------------------------

def analyze_file(path: str, rules: Dict[str, Any]) -> Tuple[str, List[DetectionResult], dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()
    results = analyze_source(src, rules)
    stats = {
        "tamanho_bytes": len(src.encode("utf-8", errors="replace")),
        "linhas": len(src.splitlines()),
        "entropia": round(shannon_entropy(src), 3),
        "maior_linha": max((len(l) for l in src.splitlines()), default=0),
    }
    return path, results, stats


def format_single_verdict(path: str, results: List[DetectionResult], stats: dict, show_evidence: bool) -> str:
    winner = pick_winner(results)
    lines = [f"\n=== {os.path.basename(path)} ==="]
    lines.append(f"  {stats['tamanho_bytes']} bytes | {stats['linhas']} linhas | "
                  f"entropia {stats['entropia']} | maior linha {stats['maior_linha']} chars")

    if winner.confidence < 15 and not winner.explicit:
        lines.append("  Veredito: NAO IDENTIFICADO")
        lines.append("  (nenhuma assinatura conhecida bateu com confianca minima -- "
                      "pode ser codigo nao ofuscado, ou um obfuscador fora da lista)")
        return "\n".join(lines)

    lines.append(f"  Veredito: {winner.display_name}  ->  {winner.confidence:.1f}% de confianca")
    if show_evidence and winner.evidences:
        lines.append("  Motivos:")
        for ev in winner.evidences:
            lines.append(f"    - {ev}")
    return "\n".join(lines)


def format_full_ranking(path: str, results: List[DetectionResult], stats: dict, show_evidence: bool) -> str:
    lines = [f"\n=== {os.path.basename(path)} ==="]
    lines.append(f"  {stats['tamanho_bytes']} bytes | {stats['linhas']} linhas | "
                  f"entropia {stats['entropia']} | maior linha {stats['maior_linha']} chars")
    ranked = sorted(results, key=lambda r: r.confidence, reverse=True)
    top = [r for r in ranked if r.confidence > 0]
    if not top:
        lines.append("  Nenhuma assinatura detectada.")
        return "\n".join(lines)
    for r in top[:10]:
        bar = "█" * int(r.confidence // 5)
        tag = " [watermark]" if r.explicit else ""
        lines.append(f"    {r.display_name:<30} {r.confidence:5.1f}%  {bar}{tag}")
        if show_evidence:
            for ev in r.evidences:
                lines.append(f"        - {ev}")
    return "\n".join(lines)


def collect_targets(path: str) -> List[str]:
    if os.path.isfile(path):
        return [path]
    targets = []
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith((".lua", ".luau", ".txt")):
                targets.append(os.path.join(root, f))
    return targets


# CLI permanece praticamente igual; apenas usa load_rules() atualizado que faz compilação
def main():
    parser = argparse.ArgumentParser(
        description="Detector de obfuscacao para scripts Lua/Roblox (mostra o veredito de maior confianca)"
    )
    parser.add_argument("path", help="Arquivo .lua/.luau/.txt ou pasta contendo varios scripts")
    parser.add_argument("--json", action="store_true", help="Saida em JSON")
    parser.add_argument("--evidence", "-e", action="store_true", help="Mostra os motivos por tras do veredito")
    parser.add_argument("--all", action="store_true", help="Mostra o ranking completo em vez de so o veredito unico")
    parser.add_argument("--rules", default=DEFAULT_RULES_PATH, help="Caminho para um signatures.json alternativo")
    parser.add_argument("--advanced", "-a", action="store_true",
                         help="Mostra análise avançada (fingerprint estrutural, scores por categoria, técnicas, "
                              "cadeia de camadas e família sem watermark). Opcional -- não afeta o veredito padrão.")
    args = parser.parse_args()

    if not os.path.isfile(args.rules):
        print(f"Arquivo de assinaturas não encontrado: {args.rules}")
        sys.exit(1)
    rules = load_rules(args.rules)

    targets = collect_targets(args.path)
    if not targets:
        print(f"Nenhum arquivo .lua/.luau/.txt encontrado em: {args.path}")
        sys.exit(1)

    if args.json:
        output = []
        for t in targets:
            path, results, stats = analyze_file(t, rules)
            if args.all:
                ranked = sorted(results, key=lambda r: r.confidence, reverse=True)
                entry = {
                    "arquivo": path,
                    "stats": stats,
                    "resultados": [
                        {"nome": r.display_name, "confianca": round(r.confidence, 2),
                         "watermark_literal": r.explicit, "evidencias": r.evidences}
                        for r in ranked if r.confidence > 0
                    ],
                }
            else:
                winner = pick_winner(results)
                entry = {
                    "arquivo": path,
                    "stats": stats,
                    "veredito": winner.display_name if (winner.confidence >= 15 or winner.explicit) else "NAO_IDENTIFICADO",
                    "confianca": round(winner.confidence, 2),
                    "watermark_literal": winner.explicit,
                    "evidencias": winner.evidences,
                }
            if args.advanced:
                entry["analise_avancada"] = _advanced_to_dict(path, results)
            output.append(entry)
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        for t in targets:
            path, results, stats = analyze_file(t, rules)
            if args.all:
                print(format_full_ranking(path, results, stats, args.evidence))
            else:
                print(format_single_verdict(path, results, stats, args.evidence))
            if args.advanced:
                try:
                    import advanced_analysis as _adv
                    with open(t, "r", encoding="utf-8", errors="replace") as f:
                        src = f.read()
                    report = _adv.run_advanced_analysis(src, results)
                    print(_adv.format_advanced_report(report))
                except ImportError:
                    print("  [advanced_analysis.py não encontrado -- coloque-o na mesma pasta pra usar --advanced]")


def _advanced_to_dict(path: str, results) -> dict:
    try:
        import advanced_analysis as _adv
    except ImportError:
        return {"erro": "advanced_analysis.py não encontrado"}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()
    report = _adv.run_advanced_analysis(src, results)
    return {
        "fingerprint": {k: v for k, v in report.fingerprint.__dict__.items()},
        "scores_por_categoria": {name: {"score": round(score, 1), "evidencias": ev}
                                  for name, (score, ev) in report.category_scores.items() if score > 0},
        "tecnicas": {name: count for name, (count, _) in report.techniques.items()},
        "cadeia_de_camadas": report.layer_chain,
        "familia_sem_watermark": [{"nome": n, "confianca": round(c, 1)} for n, c in report.family_no_watermark],
    }


if __name__ == "__main__":
    main()
