"""Global search API — doorzoekt findings, notes, commands, recordings, outputs en tasks."""

from pathlib import Path

from flask import Blueprint, jsonify, request

from app import db
from meuk.flask.models import db_bevindingen, db_bevindingen_templates, db_notes
from meuk.flask.security import require_dashboard_access

search_bp = Blueprint("search_bp", __name__)

_COMMANDS_DIR = Path("http/commands")
_LOGS_DIR = Path("meuk/logs")
_RAW_DIR = Path("raw")
_MAX_RESULTS_PER_CAT = 8


def _match(text, term):
    return term in (text or "").lower()


@search_bp.route("/api/search", methods=["GET"])
def global_search():
    require_dashboard_access()
    q = (request.args.get("q") or "").strip().lower()
    if len(q) < 2:
        return jsonify({"results": []})

    results = []

    # --- Findings ---
    finding_count = 0
    for f in db_bevindingen.query.all():
        if _match(f.naam, q) or _match(f.invoegen, q) or _match(f.uitwerken, q) or _match(f.locatie, q):
            results.append({
                "cat": "findings",
                "title": f.naam or "(geen naam)",
                "sub": f"CVSS {f.basescore}" if f.basescore else "",
                "url": f"/dashboard/findings/edit/{f.id}",
            })
            finding_count += 1
            if finding_count >= _MAX_RESULTS_PER_CAT:
                break

    # --- Finding Templates ---
    tmpl_count = 0
    for t in db_bevindingen_templates.query.all():
        if _match(t.titel, q) or _match(t.nlbeschrijving, q) or _match(t.enbeschrijving, q) or _match(t.bevtype, q):
            results.append({
                "cat": "findings",
                "title": t.titel or "(geen titel)",
                "sub": "template",
                "url": f"/dashboard/findings/add/{t.id}",
            })
            tmpl_count += 1
            if tmpl_count >= _MAX_RESULTS_PER_CAT:
                break

    # --- Notes ---
    for n in db_notes.query.order_by(db_notes.volgorde.asc()).all():
        if _match(n.naam, q) or _match(n.uitwerken, q):
            results.append({
                "cat": "notes",
                "title": n.naam or "(geen naam)",
                "sub": "rapport" if n.rapport else "",
                "url": f"/dashboard/notes/edit/{n.id}",
            })
            if len([r for r in results if r["cat"] == "notes"]) >= _MAX_RESULTS_PER_CAT:
                break

    # --- Commands ---
    cmd_count = 0
    if _COMMANDS_DIR.is_dir():
        for f in sorted(_COMMANDS_DIR.iterdir()):
            if not f.is_file():
                continue
            name = f.name
            if _match(name, q):
                results.append({
                    "cat": "commands",
                    "title": name,
                    "sub": "",
                    "url": "/dashboard/commands",
                })
                cmd_count += 1
            else:
                try:
                    content = f.read_text(errors="replace")[:2000]
                    if _match(content, q):
                        results.append({
                            "cat": "commands",
                            "title": name,
                            "sub": "content match",
                            "url": "/dashboard/commands",
                        })
                        cmd_count += 1
                except OSError:
                    pass
            if cmd_count >= _MAX_RESULTS_PER_CAT:
                break

    # --- Recordings (asciinema) ---
    rec_count = 0
    if _LOGS_DIR.is_dir():
        try:
            for f in sorted(_LOGS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
                if f.suffix == ".rec" and f.is_file() and _match(f.name, q):
                    results.append({
                        "cat": "recordings",
                        "title": f.name,
                        "sub": "",
                        "url": f"/dashboard/recordings/{f.name}",
                    })
                    rec_count += 1
                    if rec_count >= _MAX_RESULTS_PER_CAT:
                        break
        except OSError:
            pass

    # --- Loot + Outputs + Logs (alles in raw/) ---
    raw_count = 0
    if _RAW_DIR.is_dir():
        for p in sorted(_RAW_DIR.rglob("*")):
            if not p.is_file():
                continue
            rel = str(p).replace("\\", "/")
            if _match(p.name, q) or _match(rel, q):
                subdir = p.relative_to(_RAW_DIR).parts[0] if p.relative_to(_RAW_DIR).parts else ""
                cat = "loot" if subdir == "loot" else "outputs"
                results.append({
                    "cat": cat,
                    "title": p.name,
                    "sub": str(p.parent),
                    "url": f"/dashboard/outputs#{rel.replace('/', '__')}",
                })
                raw_count += 1
                if raw_count >= _MAX_RESULTS_PER_CAT * 2:
                    break

    # --- Pages (statische navigatie) ---
    pages = [
        {"title": "Dashboard", "url": "/"},
        {"title": "Tasks", "url": "/dashboard/tasks"},
        {"title": "Outputs", "url": "/dashboard/outputs"},
        {"title": "Findings", "url": "/dashboard/findings"},
        {"title": "Notes", "url": "/dashboard/notes"},
        {"title": "Files", "url": "/dashboard/files"},
        {"title": "Command Library", "url": "/dashboard/commands"},
        {"title": "Screen Terminal", "url": "/dashboard/screen"},
        {"title": "Recordings", "url": "/dashboard/recordings"},
        {"title": "Macro Generator", "url": "/dashboard/macro"},
        {"title": "Meterpreter Generator", "url": "/dashboard/meterpreter"},
        {"title": "PowerShell Generator", "url": "/dashboard/powershell"},
        {"title": "Reverse Shells", "url": "/dashboard/reverseshells"},
        {"title": "Invoke-Shellcode", "url": "/dashboard/invokeshellcode"},
        {"title": "Admin", "url": "/dashboard/admin"},
    ]
    for pg in pages:
        if _match(pg["title"], q):
            results.append({
                "cat": "pages",
                "title": pg["title"],
                "sub": pg["url"],
                "url": pg["url"],
            })

    return jsonify({"results": results})
