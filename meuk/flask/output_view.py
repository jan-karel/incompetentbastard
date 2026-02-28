from pathlib import Path

from flask import Blueprint
from flask import jsonify
from flask import render_template

from meuk.flask.security import require_dashboard_access


output_bp = Blueprint("output_bp", __name__, template_folder="html", static_folder="static")


_ALLOWED_BASES = [
    Path("raw/local"),
    Path("raw/nmap"),
    Path("raw/recon"),
    Path("raw/loot"),
    Path("raw/exploits"),
    Path("raw/tls"),
    Path("raw/debug"),
    Path("raw/mirror"),
    Path("raw/spider"),
    Path("raw/route"),
    Path("raw/tooling"),
    Path("raw/wget"),
]
_ALLOWED_SUFFIXES = {".txt", ".nmap", ".gnmap", ".xml", ".csv", ".log", ".md", ".json", ".html", ".htm", ".conf", ".cfg", ".ini", ".yaml", ".yml"}
_MAX_READ_BYTES = 120_000


def _collect_outputs():
    results = []
    for base in _ALLOWED_BASES:
        if not base.exists():
            continue

        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _ALLOWED_SUFFIXES:
                continue

            rel = str(path).replace("\\", "/")
            output_id = rel.replace("/", "__")
            results.append(
                {
                    "id": output_id,
                    "path": rel,
                    "name": path.name,
                    "size": path.stat().st_size,
                }
            )
    return results


def _resolve_output(output_id):
    rel = output_id.replace("__", "/")
    path = Path(rel)
    if not path.exists() or not path.is_file():
        return None

    normalized = path.resolve()
    for base in _ALLOWED_BASES:
        try:
            if normalized.is_relative_to(base.resolve()):
                return normalized
        except AttributeError:
            # Python < 3.9 fallback
            b = str(base.resolve())
            if str(normalized).startswith(b + "/") or str(normalized) == b:
                return normalized
    return None


@output_bp.before_request
def _guard():
    require_dashboard_access()


@output_bp.route("/dashboard/outputs", methods=["GET"])
def outputs_page():
    outputs = _collect_outputs()
    return render_template("outputs.html", outputs=outputs)


@output_bp.route("/api/outputs", methods=["GET"])
def outputs_list():
    return jsonify({"outputs": _collect_outputs()})


@output_bp.route("/api/outputs/<output_id>", methods=["GET"])
def outputs_get(output_id):
    path = _resolve_output(output_id)
    if path is None:
        return jsonify({"error": "not found"}), 404

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        content = fh.read(_MAX_READ_BYTES)

    truncated = path.stat().st_size > _MAX_READ_BYTES
    return jsonify(
        {
            "id": output_id,
            "path": str(path),
            "content": content,
            "truncated": truncated,
        }
    )
