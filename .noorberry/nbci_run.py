#!/usr/bin/env python3
"""Noorberry CI – spouštěč kontrol uvnitř GitHub Actions úlohy.

Vendoruje se do projektu jako .noorberry/nbci_run.py (generuje dev-infra, neupravovat ručně).
Topics bere z payloadu události, příkazy z .noorberry/ci.yml. Nikdy nehlásí úspěch,
pokud vybraná kontrola chybí, je neplatná nebo nebyla spuštěna.

  nbci_run.py plan   -> vypíše výstupy pro další kroky (verze nástrojů, timeout)
  nbci_run.py run    -> spustí kontroly, zapíše souhrn, návratový kód 0 jen při úplném úspěchu
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

NBCI_VERSION = "1.0.0"
CHECK_TOPICS = {"ci-lint": "lint", "ci-test": "test", "ci-build": "build", "ci-e2e": "e2e", "ci-security": "security"}
EXTENDED_TOPICS = {"ci-nightly", "ci-weekly"}
CONFIG = Path(".noorberry/ci.yml")
SCHEMA = Path(".noorberry/ci.schema.json")
ARCH_MAP = {"ARM64": "arm64", "X64": "x64"}


def _deps():
    try:
        import yaml  # noqa
        import jsonschema  # noqa
    except ImportError:
        venv = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "nbci-venv"
        if not (venv / "bin/python").exists():
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
            subprocess.run([str(venv / "bin/pip"), "install", "-q", "PyYAML==6.0.2", "jsonschema==4.23.0"], check=True)
        os.execv(str(venv / "bin/python"), [str(venv / "bin/python")] + sys.argv)


def load_event():
    p = os.environ.get("GITHUB_EVENT_PATH")
    if p and Path(p).exists():
        return json.loads(Path(p).read_text())
    return {}


def topics_from_event(event):
    return sorted(set((event.get("repository") or {}).get("topics") or []))


def requested(topics, mode):
    """Vrátí (seznam kontrol, varování). mode: push|nightly|weekly|nightly+weekly."""
    warnings = [f"neznámý topic {t}" for t in topics
                if t.startswith("ci-") and t not in CHECK_TOPICS and t not in EXTENDED_TOPICS and t != "ci-paused"]
    checks = [c for t, c in CHECK_TOPICS.items() if t in topics]
    return checks, warnings


def load_config():
    import yaml
    import jsonschema
    if not CONFIG.exists():
        return None, ["chybí .noorberry/ci.yml"]
    try:
        cfg = yaml.safe_load(CONFIG.read_text())
    except yaml.YAMLError as e:
        return None, [f"neplatný YAML: {e}"]
    schema = json.loads(SCHEMA.read_text())
    errs = sorted(jsonschema.Draft202012Validator(schema).iter_errors(cfg), key=lambda e: list(e.path))
    if errs:
        return None, [f"{'/'.join(map(str, e.path)) or '(root)'}: {e.message}" for e in errs]
    return cfg, []


def gh_output(**kv):
    out = os.environ.get("GITHUB_OUTPUT")
    lines = "".join(f"{k}={v}\n" for k, v in kv.items())
    if out:
        with open(out, "a") as f:
            f.write(lines)
    else:
        sys.stdout.write(lines)


def cmd_plan():
    cfg, errs = load_config()
    tools = (cfg or {}).get("tools", {})
    gh_output(
        valid="true" if cfg else "false",
        node=tools.get("node", ""),
        python=tools.get("python", ""),
        php=tools.get("php", ""),
        workdir=(cfg or {}).get("working_directory", "."),
    )
    for e in errs:
        print(f"::error file={CONFIG}::{e}")
    return 0


def run_cmd(cmd, cwd, env, timeout):
    """Spustí příkaz ve vlastní skupině procesů, po skončení/timeoutu ji celou ukončí."""
    start = time.monotonic()
    p = subprocess.Popen(["bash", "-eo", "pipefail", "-c", cmd], cwd=cwd, env=env, start_new_session=True)
    try:
        rc = p.wait(timeout=max(timeout, 1))
        status = "passed" if rc == 0 else "failed"
    except subprocess.TimeoutExpired:
        rc, status = None, "timeout"
    finally:
        try:
            os.killpg(p.pid, signal.SIGTERM)
            time.sleep(2)
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return status, rc, round(time.monotonic() - start, 1)


def cmd_run():
    event = load_event()
    topics = topics_from_event(event)
    mode = os.environ.get("NBCI_MODE") or "push"
    budget = int(os.environ.get("NBCI_TIMEOUT_MIN", "30")) * 60 - 60
    deadline = time.monotonic() + budget
    results, notes = [], []

    if "ci-paused" in topics:
        # Workflow by se sem nemělo dostat (job if:), ale pro jistotu.
        notes.append("repozitář má ci-paused")
        return finish("paused", results, notes, topics, mode)

    checks, warnings = requested(topics, mode)
    notes += warnings
    cfg, errs = load_config()
    if not cfg:
        notes += errs
        return finish("invalid_config", [{"check": "config", "status": "invalid", "detail": "; ".join(errs)}], notes, topics, mode)

    if mode != "push":
        ext = cfg.get("extended") or [c for c in (cfg.get("checks") or {})]
        checks = list(dict.fromkeys(checks + ext))

    arch = ARCH_MAP.get(os.environ.get("RUNNER_ARCH", ""), os.environ.get("RUNNER_ARCH", "?"))
    if arch not in cfg.get("arch", ["arm64", "x64"]):
        notes.append(f"projekt nedeklaruje podporu architektury {arch}")
        return finish("arch_unsupported", [{"check": c, "status": "not_run"} for c in checks], notes, topics, mode)

    if not checks:
        notes.append("noorberry-ci bez ci-* kontrol: provedena jen validace konfigurace")

    wd = cfg.get("working_directory", ".")
    env = dict(os.environ)
    env.update({k: str(v) for k, v in (cfg.get("env") or {}).items()})
    env["CI"] = "true"

    defs = cfg.get("checks") or {}
    # Bezpečnost jako první: čte jen soubory. Při nálezu se nic neinstaluje ani nespouští.
    if "security" in checks and "run" in (defs.get("security") or {}):
        print(f"::group::security: {defs['security']['run']}")
        st, rc, dur = run_cmd(defs["security"]["run"], wd, env, deadline - time.monotonic())
        print("::endgroup::")
        results.append({"check": "security", "status": st, "rc": rc, "seconds": dur})
        checks = [c for c in checks if c != "security"]
        if st != "passed":
            results += [{"check": c, "status": "not_run", "detail": "bezpečnostní kontrola neprošla – instalace a testy nespuštěny"}
                        for c in checks]
            return finish("failure", results, notes, topics, mode)
    install_needed = any("run" in (defs.get(c) or {}) for c in checks)
    if cfg.get("install") and install_needed:
        st, rc, dur = run_cmd(cfg["install"], wd, env, deadline - time.monotonic())
        results.append({"check": "install", "status": st, "rc": rc, "seconds": dur})
        if st != "passed":
            results += [{"check": c, "status": "not_run", "detail": "install selhal"} for c in checks]
            return finish("failure", results, notes, topics, mode)

    for c in checks:
        d = defs.get(c)
        if d is None:
            results.append({"check": c, "status": "missing", "detail": f"topic ci-{c} je zapnutý, ale ci.yml kontrolu nedefinuje"})
            continue
        if "missing" in d:
            results.append({"check": c, "status": "missing", "detail": d["missing"]})
            continue
        if d.get("requires_services") and not os.environ.get("NBCI_SERVICES_OK"):
            results.append({"check": c, "status": "missing", "detail": "vyžaduje testovací služby, ty nejsou pro tento runner ověřené"})
            continue
        left = deadline - time.monotonic()
        if left <= 5:
            results.append({"check": c, "status": "not_run", "detail": "vyčerpán časový limit"})
            continue
        print(f"::group::{c}: {d['run']}")
        st, rc, dur = run_cmd(d["run"], wd, env, left)
        print("::endgroup::")
        results.append({"check": c, "status": st, "rc": rc, "seconds": dur})

    statuses = {r["status"] for r in results}
    if statuses & {"failed", "timeout", "not_run"}:
        overall = "failure"
    elif "missing" in statuses:
        overall = "missing_config"
    else:
        overall = "success"
    return finish(overall, results, notes, topics, mode)


ICONS = {"passed": "✅", "failed": "❌", "timeout": "⏱️", "missing": "⚠️", "not_run": "⏭️", "invalid": "❌"}


def finish(overall, results, notes, topics, mode):
    data = {
        "nbci_version": NBCI_VERSION, "overall": overall, "mode": mode,
        "repo": os.environ.get("GITHUB_REPOSITORY"), "sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"), "runner": os.environ.get("RUNNER_NAME"),
        "arch": os.environ.get("RUNNER_ARCH"), "topics": topics, "results": results, "notes": notes,
    }
    Path("nbci-result.json").write_text(json.dumps(data, ensure_ascii=False, indent=2))
    lines = [f"## Noorberry CI: **{overall}** ({mode})", "", "| Kontrola | Stav | Detail |", "|---|---|---|"]
    for r in results:
        lines.append(f"| {r['check']} | {ICONS.get(r['status'], '')} {r['status']} | {r.get('detail', '')} {r.get('seconds', '')} |")
    lines += [f"- {n}" for n in notes]
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if overall == "success" else 1


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("plan", "run"):
        print(__doc__)
        sys.exit(2)
    _deps()
    sys.exit(cmd_plan() if sys.argv[1] == "plan" else cmd_run())
