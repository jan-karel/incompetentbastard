import time
from pathlib import Path

from flask import Blueprint
from flask import abort
from flask import current_app
from flask import request
from werkzeug.utils import secure_filename

from meuk.flask.security import is_local_request


upload_bp = Blueprint("upload_bp", __name__, template_folder="meuk/templates", static_folder="meuk/static")


def _is_upload_allowed():
    if current_app.config.get("PUBLIC_UPLOAD", False):
        return True
    from meuk.flask.models import db_instellingen
    s = db_instellingen.query.first()
    if s and getattr(s, 'public_upload', False):
        return True
    return is_local_request()


@upload_bp.route("/upload", methods=["POST"])
@upload_bp.route("/upload/", methods=["POST"])
def meukuploads():
    if not _is_upload_allowed():
        abort(403)

    file = request.files.get("file")
    if file is None:
        return "[*] Missing file form field 'file'", 400

    filename = secure_filename(file.filename or "")
    if not filename:
        return "[*] Empty filename", 400

    ip = secure_filename(request.remote_addr or "unknown")
    target_dir = Path("raw") / "loot" / ip
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamped = f"{int(time.time())}_{filename}"
    file.save(target_dir / timestamped)
    return "[*] Incompetent Bastard v0.42\n[+] Tot ziens en bedankt voor de vis..."


@upload_bp.route("/uploadform", methods=["GET", "POST"])
@upload_bp.route("/uploadform/", methods=["GET", "POST"])
def meukupload():
    return "ik ben het formulier"
