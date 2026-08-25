#!/usr/bin/env python3
"""Panou de progres: unde esti in proiect, intr-o singura pagina.

    make status        # ruleaza verificarile si scrie build/status.html

Nu e un serviciu. Nu asculta pe niciun port, nu executa nimic la cerere: e un
script pe care il rulezi tu si care lasa in urma un fisier HTML. Il deschizi in
browser, il inchizi, gata. (Dashboard-ul din src/triage/dashboard/ e altceva -
ala e produsul, pentru analist, si il scrii tu.)

Ce arata:
  - care dintre functiile sistemului sunt scrise si care sunt inca goale
  - teste: cate trec, cate sar, si acoperirea pe fiecare modul
  - calitate: ruff, format, mypy
  - corpus: ce cazuri exista pe disc si ce verdict asteapta fiecare
  - modele Ollama instalate
  - criteriile de acceptanta, bifate automat unde se poate

Pagina e complet autonoma: fara CSS extern, fara JavaScript, fara font-uri de pe
internet. Merge pe un VM fara retea.
"""

from __future__ import annotations

import ast
import html
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV_BIN = ROOT / ".venv" / "bin"
OUT = ROOT / "build" / "status.html"

# Modulele care compun sistemul, in ordinea in care se lucreaza la ele.
MODULES = ["parser", "analyzer", "fetcher", "drafter", "dashboard"]

# Criteriul 8.4: acoperire peste 70% pe parser si analizor.
COVERAGE_TARGET = 70.0
COVERAGE_REQUIRED_ON = ["parser", "analyzer"]


# ---------------------------------------------------------------------------
# Culegere de date
# ---------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    ok: bool | None  # None = nu se poate verifica automat
    detail: str = ""


def _run(args: list[str], timeout: int = 300) -> tuple[int, str]:
    try:
        p = subprocess.run(  # noqa: S603
            args, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    return p.returncode, (p.stdout + p.stderr).strip()


def _tool(name: str) -> str:
    local = VENV_BIN / name
    return str(local) if local.exists() else name


def unimplemented_functions() -> dict[str, list[tuple[str, bool]]]:
    """Per modul: [(nume_functie, e_scrisa)]. 'Goala' = corpul e doar
    docstring + raise NotImplementedError."""
    out: dict[str, list[tuple[str, bool]]] = {}
    for module in MODULES:
        found: list[tuple[str, bool]] = []
        base = ROOT / "src" / "triage" / module
        for path in sorted(base.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                if node.name.startswith("_"):
                    continue
                body = [n for n in node.body if not isinstance(n, ast.Expr)]
                empty = any(
                    isinstance(n, ast.Raise)
                    and isinstance(n.exc, ast.Name)
                    and n.exc.id == "NotImplementedError"
                    for n in body
                )
                found.append((node.name, not empty))
        if found:
            out[module] = found
    return out


def test_results() -> tuple[Check, dict[str, float], str]:
    code, output = _run([_tool("pytest"), "--cov-report=json:build/coverage.json"])
    line = next(
        (
            ln
            for ln in reversed(output.splitlines())
            if "passed" in ln or "failed" in ln or "error" in ln
        ),
        "",
    )
    check = Check("Teste", code == 0, line.strip() or "pytest nu a putut rula")

    coverage: dict[str, float] = {}
    cov_file = ROOT / "build" / "coverage.json"
    if cov_file.exists():
        try:
            data = json.loads(cov_file.read_text())
            for path, info in data.get("files", {}).items():
                name = (
                    Path(path).parent.name if Path(path).name == "__init__.py" else Path(path).stem
                )
                coverage[name] = float(info["summary"]["percent_covered"])
        except (OSError, ValueError, KeyError):
            pass
    return check, coverage, output


def quality_checks() -> list[Check]:
    checks = []
    code, out = _run([_tool("ruff"), "check", "src", "tests", "scripts"])
    checks.append(Check("ruff check", code == 0, "curat" if code == 0 else out.splitlines()[-1]))
    code, out = _run([_tool("ruff"), "format", "--check", "src", "tests", "scripts"])
    checks.append(Check("ruff format", code == 0, "curat" if code == 0 else out.splitlines()[-1]))
    code, out = _run([_tool("mypy")])
    checks.append(Check("mypy strict", code == 0, out.splitlines()[-1] if out else ""))
    return checks


def corpus_state() -> list[tuple[str, str, bool]]:
    """[(caz, verdict_asteptat, exista_eml)]"""
    import yaml

    rows = []
    expected_dir = ROOT / "corpus" / "expected"
    for path in sorted(expected_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        case = str(data.get("case", path.stem))
        rows.append(
            (
                case,
                str(data.get("expected_verdict", "?")),
                (ROOT / "corpus" / "eml" / f"{case}.eml").exists(),
            )
        )
    return rows


def ollama_models() -> list[str]:
    code, out = _run(["ollama", "list"], timeout=15)
    if code != 0:
        return []
    return [ln.split()[0] for ln in out.splitlines()[1:] if ln.strip()]


def acceptance_checks(
    impl: dict[str, list[tuple[str, bool]]], coverage: dict[str, float]
) -> list[Check]:
    done = {m: all(ok for _, ok in fns) for m, fns in impl.items()}
    cov_ok = all(coverage.get(m, 0.0) >= COVERAGE_TARGET for m in COVERAGE_REQUIRED_ON)

    code, _ = _run(["bash", str(ROOT / "scripts" / "check_bind_localhost.sh")], timeout=20)
    settings = ROOT / "config" / "settings.yaml"
    loopback_cfg = "127.0.0.1" in settings.read_text() if settings.exists() else False

    return [
        Check("Toate cele 11 cazuri primesc verdict corect", None, "test de scris de tine"),
        Check("Extragerea mesajului original (forward + atasament)", done.get("parser", False)),
        Check("Zero request-uri catre domenii raportate", True, "pytest-socket, blocat implicit"),
        Check("Testul de prompt injection trece", None, "acum e xfail"),
        Check("Serviciul asculta doar pe 127.0.0.1", code == 0 and loopback_cfg),
        Check("Sistemul nu trimite niciun mail", True, "nu exista cod SMTP"),
        Check(
            f"Acoperire > {COVERAGE_TARGET:.0f}% pe parser si analizor",
            cov_ok,
            ", ".join(f"{m}: {coverage.get(m, 0.0):.0f}%" for m in COVERAGE_REQUIRED_ON),
        ),
        Check("Ollama indisponibil -> fallback pe template", done.get("drafter", False)),
    ]


# ---------------------------------------------------------------------------
# Randare
# ---------------------------------------------------------------------------

CSS = """
:root{--bg:#fbfbfa;--fg:#1a1a18;--dim:#6b6b63;--line:#e2e2dc;--card:#fff;
--ok:#1a7f4b;--no:#b3261e;--wait:#8a6d00;--bar:#e8e8e2}
@media(prefers-color-scheme:dark){:root{--bg:#16161a;--fg:#e8e8e4;--dim:#9a9a92;
--line:#2c2c33;--card:#1d1d22;--ok:#4ade80;--no:#f87171;--wait:#fbbf24;--bar:#2c2c33}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.5rem;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1000px;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .2rem}
h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
margin:0 0 .75rem;font-weight:600}
.sub{color:var(--dim);font-size:.85rem;margin:0 0 1.75rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1.1rem 1.2rem}
.card.wide{grid-column:1/-1}
.row{display:flex;justify-content:space-between;gap:1rem;padding:.3rem 0;
border-bottom:1px solid var(--line);font-size:.9rem}
.row:last-child{border-bottom:0}
.row .r{color:var(--dim);font-size:.82rem;text-align:right;white-space:nowrap}
.ok{color:var(--ok)}.no{color:var(--no)}.wait{color:var(--wait)}
.big{font-size:2.2rem;font-weight:650;line-height:1;margin:.2rem 0 .1rem}
.meter{height:7px;background:var(--bar);border-radius:4px;overflow:hidden;margin:.6rem 0 .2rem}
.meter i{display:block;height:100%;background:var(--ok)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}
.next{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--ok);
border-radius:8px;padding:1rem 1.2rem;margin-bottom:1rem}
.next b{display:block;margin-bottom:.25rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}
td{padding:.28rem 0;border-bottom:1px solid var(--line)}
td:last-child{text-align:right;color:var(--dim);white-space:nowrap}
tr:last-child td{border-bottom:0}
"""


def _mark(ok: bool | None) -> str:
    if ok is True:
        return '<span class="ok">gata</span>'
    if ok is False:
        return '<span class="no">de facut</span>'
    return '<span class="wait">manual</span>'


def _rows(items: list[Check]) -> str:
    return "".join(
        f'<div class="row"><span>{html.escape(c.name)}</span>'
        f'<span class="r">{html.escape(c.detail)} {_mark(c.ok)}</span></div>'
        for c in items
    )


def render(
    impl: dict[str, list[tuple[str, bool]]],
    tests: Check,
    coverage: dict[str, float],
    quality: list[Check],
    corpus: list[tuple[str, str, bool]],
    models: list[str],
    acceptance: list[Check],
) -> str:
    total = sum(len(v) for v in impl.values())
    written = sum(1 for v in impl.values() for _, ok in v if ok)
    pct = (written / total * 100) if total else 0

    next_module = next((m for m in MODULES if any(not ok for _, ok in impl.get(m, []))), None)
    next_txt = (
        f"Urmatorul pas: <code>src/triage/{next_module}/</code>. "
        "Ordinea recomandata si ce inseamna fiecare pas sunt in README."
        if next_module
        else "Toate functiile sunt scrise. Mai raman criteriile de acceptanta de mai jos."
    )

    mod_rows = "".join(
        f'<div class="row"><span>{m}</span><span class="r">'
        f"{sum(1 for _, ok in fns if ok)}/{len(fns)} functii &middot; "
        f"{coverage.get(m, 0.0):.0f}% acoperire "
        f"{_mark(all(ok for _, ok in fns))}</span></div>"
        for m, fns in impl.items()
    )

    corpus_rows = "".join(
        f"<tr><td>{html.escape(c)}</td><td>{html.escape(v)}</td>"
        f"<td>{'pe disc' if e else '<span class=no>lipseste</span>'}</td></tr>"
        for c, v, e in corpus
    )

    model_rows = (
        "".join(
            f'<div class="row"><span><code>{html.escape(m)}</code></span></div>' for m in models
        )
        or '<div class="row"><span class="wait">Ollama nu raspunde sau nu are modele</span></div>'
    )

    return f"""<!doctype html><html lang="ro"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Progres - triaj phishing</title><style>{CSS}</style></head><body><main>
<h1>Unde esti in proiect</h1>
<p class="sub">Generat {datetime.now().strftime("%d.%m.%Y %H:%M")} cu <code>make status</code>.
Instantaneu, nu serviciu &mdash; ruleaza-l din nou ca sa il actualizezi.</p>

<div class="next"><b>{next_txt}</b></div>

<div class="grid">
  <div class="card">
    <h2>Functii scrise</h2>
    <div class="big">{written} / {total}</div>
    <div class="meter"><i style="width:{pct:.0f}%"></i></div>
    {mod_rows}
    <div class="row"><span class="r">Numara doar functiile lasate goale in schelet.
    Un modul poate arata "gata" si sa fie tot departe de ce cere foaia de task &mdash;
    criteriile de mai jos sunt masura adevarata.</span></div>
  </div>

  <div class="card">
    <h2>Verde inainte de PR</h2>
    <div class="row"><span>{html.escape(tests.name)}</span>
      <span class="r">{html.escape(tests.detail)} {_mark(tests.ok)}</span></div>
    {_rows(quality)}
  </div>

  <div class="card">
    <h2>Modele Ollama</h2>
    {model_rows}
    <div class="row"><span class="r">Ce model folosesti e decizia ta.</span></div>
  </div>

  <div class="card wide">
    <h2>Criterii de acceptanta</h2>
    {_rows(acceptance)}
  </div>

  <div class="card wide">
    <h2>Corpus</h2>
    <table>{corpus_rows}</table>
  </div>
</div>
</main></body></html>"""


def main() -> int:
    print("verific... (ruleaza pytest, ruff si mypy, dureaza cateva secunde)")
    impl = unimplemented_functions()
    tests, coverage, _ = test_results()
    quality = quality_checks()
    corpus = corpus_state()
    models = ollama_models()
    acceptance = acceptance_checks(impl, coverage)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        render(impl, tests, coverage, quality, corpus, models, acceptance), encoding="utf-8"
    )

    written = sum(1 for v in impl.values() for _, ok in v if ok)
    total = sum(len(v) for v in impl.values())
    print(f"  functii scrise : {written}/{total}")
    print(f"  teste          : {tests.detail}")
    for c in quality:
        print(f"  {c.name:<14} : {'ok' if c.ok else 'PICA'}")
    print(f"\nDeschide: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
