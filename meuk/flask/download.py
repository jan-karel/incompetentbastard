import io
import logging
import shutil
import subprocess
import time
from pathlib import Path

from flask import Blueprint
from flask import abort
from flask import current_app
from flask import jsonify
from flask import render_template
from flask import request
from flask import send_file
from flask import send_from_directory
from werkzeug.utils import secure_filename

from meuk.flask.security import dashboard_access_allowed
from meuk.flask.security import require_dashboard_access


download_bp = Blueprint("download_bp", __name__, template_folder="templates", static_folder="static")

_log = logging.getLogger(__name__)

_ALLOWED_LOCAL_IPS = {"127.0.0.1", "::1"}

_PREVIEWABLE = {
    ".ps1", ".sh", ".txt", ".py", ".conf", ".cfg", ".ini",
    ".yaml", ".yml", ".xml", ".json", ".md", ".bat", ".cmd",
    ".cs", ".vbs", ".js", ".html", ".css", ".sql", ".rb",
    ".pl", ".lua", ".asp", ".aspx", ".jsp", ".log", ".csv",
}
_MAX_PREVIEW = 50_000

_VALID_TECHNIQUES = ("mixed", "subexpr", "format", "chararray", "backtick")
_OBFUSCATABLE = {".php", ".aspx", ".py", ".hta", ".txt"}
_OBFUSCATABLE_ALL = _OBFUSCATABLE | {".ps1"}

_SCAN_ROOTS = {
    "tools_mini": Path("http/tools/mini"),
    "tools": Path("http/tools"),
    "payloads": Path("http/payloads"),
}

# In-memory signature cache met TTL
_sig_cache = None
_sig_cache_time = 0.0
_SIG_CACHE_TTL = 10800  # 3 uur


def _get_signatures():
    """Haal signatures op met in-memory cache (TTL 5 min)."""
    global _sig_cache, _sig_cache_time
    now = time.monotonic()
    if _sig_cache is not None and (now - _sig_cache_time) < _SIG_CACHE_TTL:
        return _sig_cache
    try:
        from obfuscate_ps import build_signatures
    except ImportError:
        return None
    try:
        _sig_cache = build_signatures()
    except Exception as exc:
        _log.warning("build_signatures mislukt: %s", exc)
        return None
    _sig_cache_time = now
    return _sig_cache


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


def _obfuscate_on_the_fly(file_path, technique='mixed'):
    """Obfusceer een .ps1 bestand on-the-fly en return een BytesIO stream."""
    try:
        from obfuscate_ps import UTF8_BOM, detect_bom, obfuscate_file
    except ImportError:
        _log.warning("obfuscate_ps niet beschikbaar, obfuscatie overgeslagen")
        return None

    if not Path(file_path).is_file():
        return None

    try:
        with open(file_path, 'rb') as f:
            raw = f.read()
        has_bom, content_bytes = detect_bom(raw)
        content = content_bytes.decode('utf-8')
    except (OSError, UnicodeDecodeError) as exc:
        _log.warning("Kan %s niet lezen voor obfuscatie: %s", file_path, exc)
        return None

    lines = content.splitlines(keepends=True)
    signatures = _get_signatures()
    if signatures is None:
        return None

    try:
        new_lines, stats, _ = obfuscate_file(lines, signatures, technique)
    except Exception as exc:
        _log.warning("obfuscate_file mislukt voor %s: %s", Path(file_path).name, exc)
        return None

    if stats["lines_changed"] == 0:
        return None

    _log.info("Obfuscatie %s: %d string, %d code over %d regels (techniek=%s)",
              Path(file_path).name, stats["string"], stats["code"],
              stats["lines_changed"], technique)

    output_bytes = ''.join(new_lines).encode('utf-8')
    if has_bom:
        output_bytes = UTF8_BOM + output_bytes
    return io.BytesIO(output_bytes)


def _obfuscate_text_on_the_fly(file_path):
    """Obfusceer een text-based payload on-the-fly en return een BytesIO stream."""
    try:
        from obfuscate_av import obfuscate_text, detect_language
    except ImportError:
        _log.warning("obfuscate_av niet beschikbaar, obfuscatie overgeslagen")
        return None

    p = Path(file_path)
    if not p.is_file():
        return None

    language = detect_language(p.name)
    if language is None:
        return None

    try:
        content = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        _log.warning("Kan %s niet lezen voor obfuscatie: %s", file_path, exc)
        return None

    try:
        result, stats = obfuscate_text(content, language)
    except Exception as exc:
        _log.warning("obfuscate_text mislukt voor %s: %s", p.name, exc)
        return None

    total = stats.get("string", 0) + stats.get("code", 0)
    if total == 0:
        return None

    _log.info("Multi-taal obfuscatie %s (%s): %d string, %d code",
              p.name, language, stats.get("string", 0), stats.get("code", 0))
    return io.BytesIO(result.encode("utf-8"))


def _download_or_404(directory, filename):
    if not _downloads_allowed():
        abort(403)

    candidate = Path(directory) / filename
    if candidate.is_file():
        ext = candidate.suffix.lower()
        if ext == '.ps1':
            obf_override = request.args.get('obf')
            if obf_override is not None:
                do_obfuscate = obf_override == '1'
            else:
                from meuk.flask.models import db_instellingen
                s = db_instellingen.query.first()
                do_obfuscate = bool(getattr(s, 'obfuscate_downloads', False))
            if do_obfuscate:
                technique_override = request.args.get('technique', '').strip()
                if technique_override in _VALID_TECHNIQUES:
                    technique = technique_override
                else:
                    from meuk.flask.models import db_instellingen
                    s = db_instellingen.query.first()
                    technique = getattr(s, 'obfuscate_technique', 'mixed') or 'mixed'
                result = _obfuscate_on_the_fly(str(candidate), technique)
                if result is not None:
                    return send_file(result, as_attachment=True,
                                     download_name=filename,
                                     mimetype='application/octet-stream')
        elif ext in _OBFUSCATABLE:
            obf_override = request.args.get('obf')
            if obf_override is not None:
                do_obfuscate = obf_override == '1'
            else:
                from meuk.flask.models import db_instellingen
                s = db_instellingen.query.first()
                do_obfuscate = bool(getattr(s, 'obfuscate_downloads', False))
            if do_obfuscate:
                result = _obfuscate_text_on_the_fly(str(candidate))
                if result is not None:
                    return send_file(result, as_attachment=True,
                                     download_name=filename,
                                     mimetype='application/octet-stream')
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
            "obfuscatable": p.suffix.lower() in _OBFUSCATABLE_ALL,
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


@download_bp.route("/api/files/scan/<category>/<path:filename>", methods=["POST"])
def api_files_scan(category, filename):
    require_dashboard_access()
    base = _SCAN_ROOTS.get(category)
    if base is None:
        abort(404)
    target = (base / filename).resolve()
    if not str(target).startswith(str(base.resolve())):
        abort(403)
    if not target.is_file():
        abort(404)

    clamscan = shutil.which("clamscan")
    if not clamscan:
        return jsonify({"status": "unavailable", "output": "clamscan niet gevonden op dit systeem"})

    try:
        proc = subprocess.run(
            [clamscan, "--no-summary", str(target)],
            capture_output=True, text=True, timeout=60,
        )
        output = (proc.stdout + proc.stderr).strip()
        if "No supported database files found" in output:
            return jsonify({
                "status": "unavailable",
                "output": "ClamAV virusdatabase ontbreekt.\nVoer uit: freshclam\n\n" + output,
            })
        if proc.returncode == 0:
            status = "clean"
        elif proc.returncode == 1:
            status = "infected"
        else:
            status = "error"
        return jsonify({"status": status, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "output": "Scan time-out (>60s)"})
    except Exception as exc:
        return jsonify({"status": "error", "output": str(exc)})


@download_bp.route("/api/files/obfuscate/<category>/<path:filename>", methods=["GET"])
def api_files_obfuscate(category, filename):
    """Obfusceer on-the-fly en stuur als download."""
    require_dashboard_access()
    base = _SCAN_ROOTS.get(category)
    if base is None:
        abort(404)
    target = (base / filename).resolve()
    if not str(target).startswith(str(base.resolve())):
        abort(403)
    if not target.is_file():
        abort(404)

    ext = target.suffix.lower()
    if ext not in _OBFUSCATABLE_ALL:
        abort(400, description="Bestandstype niet obfusceerbaar")

    if ext == ".ps1":
        result = _obfuscate_on_the_fly(str(target))
    else:
        result = _obfuscate_text_on_the_fly(str(target))

    if result is None:
        abort(500, description="Obfuscatie mislukt of geen signatures gevonden")

    return send_file(result, as_attachment=True,
                     download_name=target.name,
                     mimetype="application/octet-stream")


@download_bp.route("/api/files/obfuscate/<category>/<path:filename>", methods=["POST"])
def api_files_obfuscate_inplace(category, filename):
    """Obfusceer het bestand in-place (overschrijf op server)."""
    require_dashboard_access()
    base = _SCAN_ROOTS.get(category)
    if base is None:
        abort(404)
    target = (base / filename).resolve()
    if not str(target).startswith(str(base.resolve())):
        abort(403)
    if not target.is_file():
        abort(404)

    ext = target.suffix.lower()
    if ext not in _OBFUSCATABLE_ALL:
        return jsonify({"ok": False, "message": "Bestandstype niet obfusceerbaar"})

    if ext == ".ps1":
        result = _obfuscate_on_the_fly(str(target))
    else:
        result = _obfuscate_text_on_the_fly(str(target))

    if result is None:
        return jsonify({"ok": False, "message": "Obfuscatie mislukt of geen signatures gevonden"})

    try:
        target.write_bytes(result.getvalue())
    except OSError as exc:
        return jsonify({"ok": False, "message": str(exc)})

    _log.info("In-place obfuscatie: %s/%s", category, filename)
    return jsonify({"ok": True, "message": f"{filename} succesvol overschreven"})


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
