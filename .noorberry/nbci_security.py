#!/usr/bin/env python3
"""Noorberry CI – bezpečnostní kontrola repozitáře BEZ spuštění jeho kódu.

Čte jen soubory a historii gitu:
  osv      známé zranitelnosti a ŠKODLIVÉ balíčky (OSV, záznamy MAL-*) z lockfile/requirements
  origin   původ npm balíčků: jen https://registry.npmjs.org/, s kontrolním součtem; výpis instalačních skriptů
  secrets  úniky tajemství v celé historii gitu (gitleaks, hodnoty se nikdy nevypisují)
  code     rizikový kód (semgrep p/default; bandit pro Python)
  workflow nebezpečné konstrukce v GitHub Actions (zizmor, offline)

Použití: nbci_security.py [ADRESÁŘ_REPA] [--json VÝSTUP]
Návratový kód 1 = blokující nález (škodlivý balíček, kritická/vysoká zranitelnost, tajemství,
cizí registr, chyba nástroje). Nástroj, který nejde spustit, je chyba – nikdy tichý úspěch.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(os.environ.get("NBCI_TOOLS", "/opt/noorberry-ci/tools"))
# Připnuté verze a SHA256 (ze SHA256SUMS/checksums vydání). Na Oracle předinstalováno, jinde --install-tools.
BINARIES = {
    "osv-scanner": ("https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_{a}", None,
                    {"amd64": "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b",
                     "arm64": "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7"}),
    "gitleaks": ("https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_{a}.tar.gz", "gitleaks",
                 {"x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
                  "arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"}),
}
PIP_TOOLS = ["semgrep==1.182.1", "zizmor==1.31.1", "bandit==1.9.4"]


def install_tools(dest):
    """Stáhne nástroje do dest s ověřením SHA256. Při nesouladu končí chybou."""
    import hashlib
    import platform
    import tarfile
    import urllib.request
    arm = platform.machine() in ("aarch64", "arm64")
    (dest / "bin").mkdir(parents=True, exist_ok=True)
    for name, (url, member, sums) in BINARIES.items():
        key = "arm64" if arm else ("amd64" if "amd64" in sums else "x64")
        data = urllib.request.urlopen(url.format(a=key), timeout=120).read()
        if hashlib.sha256(data).hexdigest() != sums[key]:
            raise SystemExit(f"{name}: kontrolní součet nesouhlasí – nástroj odmítnut")
        target = dest / "bin" / name
        if member:
            import io
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                target.write_bytes(tf.extractfile(member).read())
        else:
            target.write_bytes(data)
        target.chmod(0o755)
    subprocess.run([sys.executable, "-m", "venv", str(dest / "venv")], check=True)
    subprocess.run([str(dest / "venv/bin/pip"), "install", "-q", *PIP_TOOLS], check=True)
SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv"}


def tool(name):
    for p in (TOOLS / "bin" / name, TOOLS / "venv/bin" / name):
        if p.exists():
            return str(p)
    return shutil.which(name)


def run(cmd, timeout=900, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return None, "", "timeout"


class Report:
    def __init__(self):
        self.findings, self.errors, self.info = [], [], []

    def add(self, check, severity, title, where="", blocking=False):
        self.findings.append({"check": check, "severity": severity, "title": title, "where": where, "blocking": blocking})

    def error(self, check, msg):
        self.errors.append({"check": check, "error": msg[:300]})


def cvss_level(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def check_osv(repo, rep):
    exe = tool("osv-scanner")
    if not exe:
        return rep.error("osv", "osv-scanner není k dispozici")
    rc, out, err = run([exe, "scan", "source", "-r", "--format", "json", str(repo)])
    if rc not in (0, 1) or not out.strip():
        if "No package sources found" in err or "no package sources found" in err.lower():
            rep.info.append("osv: žádné lockfile/requirements – není co kontrolovat")
            return
        return rep.error("osv", f"rc={rc} {err.strip()[-300:]}")
    data = json.loads(out)
    for res in data.get("results") or []:
        src = os.path.relpath(res["source"]["path"], repo)
        for pkg in res.get("packages") or []:
            name = f"{pkg['package']['name']}@{pkg['package'].get('version', '?')}"
            groups = {tuple(g["ids"]): g for g in pkg.get("groups") or []}
            for g_ids, g in groups.items():
                ids = sorted(g_ids)
                if any(i.startswith("MAL-") for i in ids):
                    rep.add("osv", "critical", f"ŠKODLIVÝ BALÍČEK {name} ({', '.join(ids)})", src, True)
                    continue
                lvl = cvss_level(g.get("max_severity"))
                rep.add("osv", lvl, f"{name}: {', '.join(ids)[:120]}", src, lvl in ("critical", "high"))


def check_origin(repo, rep):
    for lock in repo.rglob("package-lock.json"):
        if SKIP_DIRS & set(lock.relative_to(repo).parts[:-1]):
            continue
        rel = str(lock.relative_to(repo))
        try:
            pk = json.loads(lock.read_text()).get("packages") or {}
        except (ValueError, OSError) as e:
            rep.error("origin", f"{rel}: {e}")
            continue
        scripts = []
        for path, meta in pk.items():
            if not path or meta.get("link"):
                continue
            res = meta.get("resolved")
            if res and not res.startswith("https://registry.npmjs.org/"):
                rep.add("origin", "high", f"balíček z jiného zdroje než npm registr: {path.split('node_modules/')[-1]} ← {res[:80]}", rel, True)
            elif res and not meta.get("integrity"):
                rep.add("origin", "high", f"chybí kontrolní součet: {path.split('node_modules/')[-1]}", rel, True)
            if meta.get("hasInstallScript"):
                scripts.append(path.split("node_modules/")[-1])
        if scripts:
            rep.add("origin", "info", f"instalační skripty ({len(scripts)}): {', '.join(sorted(scripts))[:200]} – v CI se nespouští (--ignore-scripts)", rel)


def check_secrets(repo, rep):
    exe = tool("gitleaks")
    if not exe:
        return rep.error("secrets", "gitleaks není k dispozici")
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "gl.json"
        mode = "git" if (repo / ".git").exists() else "dir"
        rc, _, err = run([exe, mode, str(repo), "--redact", "--no-banner", "--report-format", "json",
                          "--report-path", str(out), "--exit-code", "3"])
        if rc not in (0, 3):
            return rep.error("secrets", f"rc={rc} {err.strip()[-300:]}")
        leaks = json.loads(out.read_text() or "[]") if out.exists() else []
    seen = set()
    for lk in leaks:
        key = (lk.get("RuleID"), lk.get("File"))
        if key in seen:
            continue
        seen.add(key)
        commit = (lk.get("Commit") or "")[:7]
        rep.add("secrets", "high", f"{lk.get('RuleID')} (hodnota skryta)", f"{lk.get('File')}" + (f" @ {commit}" if commit else ""), True)


def check_code(repo, rep):
    exe = tool("semgrep")
    if exe:
        rc, out, err = run([exe, "scan", "--config", "p/default", "--json", "--metrics=off", "--quiet",
                            "--timeout", "30", str(repo)], timeout=1200)
        if rc in (0, 1) and out.strip():
            for r in json.loads(out).get("results") or []:
                sev = {"ERROR": "high", "WARNING": "medium"}.get(r["extra"].get("severity"), "low")
                rep.add("code", sev, r["check_id"].split(".")[-1], f"{os.path.relpath(r['path'], repo)}:{r['start']['line']}", False)
        else:
            rep.error("code", f"semgrep rc={rc} {err.strip()[-300:]}")
    else:
        rep.error("code", "semgrep není k dispozici")
    if any(repo.rglob("*.py")):
        exe = tool("bandit")
        if not exe:
            return rep.error("code", "bandit není k dispozici")
        rc, out, err = run([exe, "-r", str(repo), "-f", "json", "-q", "-ll", "-x",
                            ",".join(str(repo / d) for d in SKIP_DIRS)])
        if rc in (0, 1) and out.strip():
            for r in json.loads(out).get("results") or []:
                sev = r["issue_severity"].lower()
                rep.add("code", sev, f"bandit {r['test_id']}: {r['issue_text'][:90]}", f"{os.path.relpath(r['filename'], repo)}:{r['line_number']}", False)
        else:
            rep.error("code", f"bandit rc={rc} {err.strip()[-300:]}")


def check_workflows(repo, rep):
    wf = repo / ".github/workflows"
    if not wf.is_dir():
        return
    exe = tool("zizmor")
    if not exe:
        return rep.error("workflow", "zizmor není k dispozici")
    rc, out, err = run([exe, "--offline", "--format", "json", "--no-progress", str(wf)])
    if rc is None or not out.strip():
        return rep.error("workflow", f"zizmor rc={rc} {err.strip()[-300:]}")
    for r in json.loads(out):
        sev = (r.get("determinations") or {}).get("severity", "Unknown").lower()
        loc = ((r.get("locations") or [{}])[0].get("symbolic") or {}).get("key", {})
        where = (loc.get("Local") or {}).get("given_path", "") if isinstance(loc, dict) else ""
        rep.add("workflow", sev, f"{r.get('ident')}: {r.get('desc', '')[:90]}", os.path.relpath(where, repo) if where else "", sev == "high")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--json")
    ap.add_argument("--install-tools", action="store_true", help="chybějící nástroje stáhnout (GitHub-hosted)")
    a = ap.parse_args()
    global TOOLS
    if a.install_tools and not (TOOLS / "bin/osv-scanner").exists():
        TOOLS = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "nbci-tools"
        install_tools(TOOLS)
    repo = Path(a.repo).resolve()
    rep = Report()
    for fn in (check_osv, check_origin, check_secrets, check_code, check_workflows):
        try:
            fn(repo, rep)
        except Exception as e:  # noqa: BLE001 – selhání nástroje = chyba, ne úspěch
            rep.error(fn.__name__, repr(e))
    blocking = [f for f in rep.findings if f["blocking"]]
    overall = "error" if rep.errors else "failure" if blocking else "success"
    data = {"repo": repo.name, "overall": overall, "findings": rep.findings, "errors": rep.errors, "info": rep.info}
    if a.json:
        Path(a.json).write_text(json.dumps(data, ensure_ascii=False, indent=2))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    print(f"## Bezpečnostní kontrola {repo.name}: **{overall}**")
    for f in sorted(rep.findings, key=lambda f: (not f["blocking"], order.get(f["severity"], 5))):
        print(f"- [{f['severity']}{' BLOKUJE' if f['blocking'] else ''}] {f['check']}: {f['title']} {('(' + f['where'] + ')') if f['where'] else ''}")
    for e in rep.errors:
        print(f"- [CHYBA NÁSTROJE] {e['check']}: {e['error']}")
    for i in rep.info:
        print(f"- [info] {i}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(f"Bezpečnost: {overall}, blokujících nálezů {len(blocking)}, chyb nástrojů {len(rep.errors)}\n")
    return 0 if overall == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
