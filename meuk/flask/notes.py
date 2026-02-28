"""Notes blueprint — CRUD voor db_notes."""

from flask import Blueprint, jsonify, redirect, render_template, request

from app import db
from meuk.flask.models import db_notes
from meuk.flask.security import require_dashboard_access


notes_bp = Blueprint("notes_bp", __name__, template_folder="html", static_folder="static")


@notes_bp.before_request
def _guard():
    require_dashboard_access()


@notes_bp.route("/dashboard/notes", methods=["GET"])
def notes_page():
    notes = db_notes.query.order_by(db_notes.volgorde.asc(), db_notes.id.desc()).all()
    return render_template("notes_overview.html", notes=notes)


@notes_bp.route("/dashboard/notes/add", methods=["POST"])
def notes_add():
    naam = request.form.get("naam", "").strip()
    uitwerken = request.form.get("uitwerken", "").strip()
    if naam:
        note = db_notes(naam=naam, uitwerken=uitwerken)
        db.session.add(note)
        db.session.commit()
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": True, "id": note.id, "naam": note.naam})
    elif request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": False, "error": "naam is verplicht"}), 400
    return redirect("/dashboard/notes")


@notes_bp.route("/dashboard/notes/edit/<int:note_id>", methods=["GET", "POST"])
def notes_edit(note_id):
    note = db.get_or_404(db_notes, note_id)
    if request.method == "POST":
        note.naam = request.form.get("naam", "").strip()
        note.uitwerken = request.form.get("uitwerken", "").strip()
        db.session.commit()
        return redirect("/dashboard/notes")
    return render_template("notes_edit.html", note=note)


@notes_bp.route("/dashboard/notes/delete/<int:note_id>", methods=["GET"])
def notes_delete(note_id):
    note = db.get_or_404(db_notes, note_id)
    db.session.delete(note)
    db.session.commit()
    return redirect("/dashboard/notes")


@notes_bp.route("/api/notes", methods=["GET"])
def notes_api():
    notes = db_notes.query.order_by(db_notes.volgorde.asc(), db_notes.id.desc()).all()
    return jsonify({
        "notes": [
            {
                "id": n.id,
                "naam": n.naam,
                "uitwerken": n.uitwerken,
                "rapport": n.rapport or False,
                "volgorde": n.volgorde or 0,
            }
            for n in notes
        ]
    })


@notes_bp.route("/api/notes/reorder", methods=["POST"])
def notes_reorder():
    data = request.get_json(silent=True)
    if not data or "order" not in data:
        return jsonify({"ok": False, "error": "order array ontbreekt"}), 400
    order = data["order"]
    for idx, note_id in enumerate(order):
        note = db.session.get(db_notes, note_id)
        if note:
            note.volgorde = idx
    db.session.commit()
    return jsonify({"ok": True})


@notes_bp.route("/api/notes/<int:note_id>", methods=["PUT"])
def notes_update_api(note_id):
    note = db.get_or_404(db_notes, note_id)
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "geen JSON body"}), 400
    naam = data.get("naam", "").strip()
    if not naam:
        return jsonify({"ok": False, "error": "naam is verplicht"}), 400
    note.naam = naam
    note.uitwerken = data.get("uitwerken", "").strip()
    db.session.commit()
    return jsonify({"ok": True, "id": note.id, "naam": note.naam})


@notes_bp.route("/api/notes/<int:note_id>/toggle-rapport", methods=["POST"])
def notes_toggle_rapport(note_id):
    note = db.get_or_404(db_notes, note_id)
    note.rapport = not (note.rapport or False)
    db.session.commit()
    return jsonify({"ok": True, "rapport": note.rapport})
