from pathlib import Path

from flask import Blueprint
from flask import abort
from flask import current_app
from flask import jsonify
from flask import render_template
from flask import request
from flask import send_from_directory
from werkzeug.utils import secure_filename

from meuk.flask.security import dashboard_access_allowed
from meuk.flask.security import require_dashboard_access


download_bp = Blueprint("download_bp", __name__, template_folder="templates", static_folder="static")


_ALLOWED_LOCAL_IPS = {"127.0.0.1", "::1"}

_PREVIEWABLE = {
    ".ps1", ".sh", ".txt", ".py", ".conf", ".cfg", ".ini",
    ".yaml", ".yml", ".xml", ".json", ".md", ".bat", ".cmd",
    ".cs", ".vbs", ".js", ".html", ".css", ".sql", ".rb",
    ".pl", ".lua", ".asp", ".aspx", ".jsp", ".log", ".csv",
}
_MAX_PREVIEW = 50_000


def _downloads_allowed():
    if current_app.config.get("PUBLIC_DOWNLOADS", False):
        return True
    from meuk.flask.models import db_instellingen
    s = db_instellingen.query.first()
    if s and (getattr(s, 'public_downloads', False) or getattr(s, 'public_payloads', False)):
        return True
    if request.remote_addr in _ALLOWED_LOCAL_IPS:
        return True
    return dashboard_access_allowed()


def _download_or_404(directory, filename):
    if not _downloads_allowed():
        abort(403)

    candidate = Path(directory) / filename
    if candidate.is_file():
        return send_from_directory(directory, filename, as_attachment=True)
    abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")


@download_bp.route("/p/<bestand>", methods=["GET"])
@download_bp.route("/payloads/<bestand>", methods=["GET"])
def payload_download(bestand):
    return _download_or_404("http/payloads", bestand)


@download_bp.route("/t/<bestand>", methods=["GET"])
@download_bp.route("/tools/<bestand>", methods=["GET"])
def tools_download(bestand):
    return _download_or_404("http/tools", bestand)


@download_bp.route("/tm/<bestand>", methods=["GET"])
@download_bp.route("/tools/mini/<bestand>", methods=["GET"])
def mimi_download(bestand):
    return _download_or_404("http/tools/mini", bestand)


def _file_info(base_path, url_prefix):
    base = Path(base_path)
    if not base.is_dir():
        return []
    result = []
    for p in sorted(base.iterdir()):
        if not p.is_file():
            continue
        st = p.stat()
        result.append({
            "name": p.name,
            "size": st.st_size,
            "modified": st.st_mtime,
            "url": f"{url_prefix}/{p.name}",
            "previewable": p.suffix.lower() in _PREVIEWABLE,
        })
    return result


@download_bp.route("/api/files", methods=["GET"])
def api_files():
    require_dashboard_access()
    return jsonify({
        "tools_mini": _file_info("http/tools/mini", "/tm"),
        "tools": _file_info("http/tools", "/t"),
        "payloads": _file_info("http/payloads", "/p"),
    })


@download_bp.route("/api/files/loot", methods=["GET"])
def api_files_loot():
    require_dashboard_access()
    loot_root = Path("raw/loot")
    if not loot_root.is_dir():
        return jsonify({})
    result = {}
    for ip_dir in sorted(loot_root.iterdir()):
        if not ip_dir.is_dir():
            continue
        files = []
        for p in sorted(ip_dir.iterdir()):
            if not p.is_file():
                continue
            st = p.stat()
            files.append({
                "name": p.name,
                "size": st.st_size,
                "modified": st.st_mtime,
                "url": f"/loot/{ip_dir.name}/{p.name}",
                "previewable": p.suffix.lower() in _PREVIEWABLE,
            })
        if files:
            result[ip_dir.name] = files
    return jsonify(result)


@download_bp.route("/api/files/preview/<category>/<path:filename>", methods=["GET"])
def api_files_preview(category, filename):
    require_dashboard_access()
    roots = {
        "tools_mini": Path("http/tools/mini"),
        "tools": Path("http/tools"),
        "payloads": Path("http/payloads"),
        "loot": Path("raw/loot"),
    }
    base = roots.get(category)
    if base is None:
        abort(404)
    target = (base / filename).resolve()
    if not str(target).startswith(str(base.resolve())):
        abort(403)
    if not target.is_file():
        abort(404)
    if target.suffix.lower() not in _PREVIEWABLE:
        abort(403, description="File type not previewable")
    try:
        content = target.read_text(errors="replace")[:_MAX_PREVIEW]
    except Exception:
        abort(500, description="Could not read file")
    return jsonify({"name": target.name, "content": content})


@download_bp.route("/loot/<ip>/<bestand>", methods=["GET"])
def loot_download(ip, bestand):
    safe_ip = secure_filename(ip)
    if not safe_ip:
        abort(404)
    return _download_or_404(f"raw/loot/{safe_ip}", bestand)


@download_bp.route("/dashboard/bestanden", methods=["GET"])
@download_bp.route("/dashboard/bestanden/", methods=["GET"])
def dashboard_bestanden():
    require_dashboard_access()
    files = sorted([p.name for p in Path("http/tools/mini").glob("*") if p.is_file()])
    return "\n".join(files), 200, {"Content-Type": "text/plain; charset=utf-8"}


@download_bp.route("/dashboard/payloads", methods=["GET"])
@download_bp.route("/dashboard/payloads/", methods=["GET"])
def dashboard_payloads():
    require_dashboard_access()
    files = sorted([p.name for p in Path("http/payloads").glob("*") if p.is_file()])
    return "\n".join(files), 200, {"Content-Type": "text/plain; charset=utf-8"}


@download_bp.route("/dashboard/files", methods=["GET"])
def dashboard_files():
    require_dashboard_access()

    tools_mini = _file_info("http/tools/mini", "/tm")
    tools = _file_info("http/tools", "/t")
    payloads = _file_info("http/payloads", "/p")
    return render_template("files.html", tools_mini=tools_mini, tools=tools, payloads=payloads)
