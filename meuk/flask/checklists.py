"""Checklists blueprint — pentest checklist management."""

import datetime
import json
import os

from flask import Blueprint, jsonify, render_template, request

from app import db
from meuk.flask.models import (
    db_bevindingen,
    db_bevindingen_templates,
    db_checklist,
    db_checklist_item,
    db_instellingen,
    db_notes,
)
from meuk.flask.security import require_dashboard_access


def _get_scope_targets():
    """Haal scope targets op uit instellingen."""
    s = db_instellingen.query.first()
    try:
        return json.loads(getattr(s, 'rapport_scope_targets', '[]') or '[]')
    except (json.JSONDecodeError, TypeError):
        return []

checklists_bp = Blueprint(
    "checklists_bp", __name__, template_folder="html", static_folder="static"
)

_JSON_PATH = os.path.join(os.path.dirname(__file__), "db", "checklists.json")

# Fase-beschrijvingen — korte uitleg per fase voor de guided UX.
PHASE_DESCRIPTIONS = {
    # Extern
    "ext_recon": "Verzamel informatie over het doelwit voordat je begint met actief testen. DNS, OSINT, subdomeinen en certificaten.",
    "ext_webenum": "Breng de webapplicatie in kaart: technologie-stack, directories, virtual hosts en API-endpoints.",
    "ext_webapp": "Test de webapplicatie op kwetsbaarheden: injectie, authenticatie, access control en logica-fouten.",
    "ext_services": "Onderzoek netwerk-services buiten HTTP: FTP, SSH, SMTP, SNMP en andere open poorten.",
    "ext_access": "Probeer toegang te verkrijgen tot het systeem via gevonden kwetsbaarheden of zwakke credentials.",
    "ext_postexploit": "Na initieel toegang: escaleer rechten, verzamel credentials en breid je positie uit.",
    "ext_report": "Documenteer alle bevindingen, maak screenshots van bewijs en schrijf het rapport.",
    # Intern
    "int_netdisc": "Ontdek het interne netwerk: subnets, live hosts, routing en netwerk-segmentatie.",
    "int_svc": "Enumereer services op gevonden hosts: open poorten, versies, bekende kwetsbaarheden.",
    "int_ad": "Breng de Active Directory-omgeving in kaart: gebruikers, groepen, GPO's, trusts en ACL's.",
    "int_cred": "Verzamel credentials: LSASS dumps, Kerberoasting, responder, LAPS en opgeslagen wachtwoorden.",
    "int_privesc": "Escaleer privileges op het lokale systeem: service misconfigs, UAC bypass, token impersonation.",
    "int_lateral": "Beweeg lateraal door het netwerk: PSRemoting, WMI, DCOM, SMB en pass-the-hash.",
    "int_domdom": "Bereik domein-dominantie: DCSync, Golden/Silver tickets, trust-abuse en forest-escalatie.",
    "int_persist": "Zet persistence-mechanismen op en documenteer de impact van volledige compromittering.",
    "int_linux": "Test Linux-systemen en cloud-omgevingen: sudo, SUID, cron, containers en cloud metadata.",
    "int_report": "Documenteer alle bevindingen, maak screenshots van bewijs en schrijf het rapport.",
}

# Info over checklist-types voor de overview kaarten.
CHECKLIST_TYPE_INFO = {
    "extern": {
        "icon": "globe",
        "scope": "Web, netwerk, exploitatie",
        "description": "Pentest vanuit het perspectief van een externe aanvaller. "
        "Test publiek bereikbare systemen, webapplicaties en netwerk-services.",
    },
    "intern": {
        "icon": "server",
        "scope": "AD, laterale beweging, domein-dominantie",
        "description": "Pentest vanuit het interne netwerk. "
        "Test Active Directory, laterale beweging, privilege escalation en domein-dominantie.",
    },
}


def _load_templates():
    with open(_JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _find_item_in_template(data, checklist_type, item_ref):
    cl = data.get("checklists", {}).get(checklist_type)
    if not cl:
        return None
    for phase in cl.get("phases", []):
        for item in phase.get("items", []):
            if item["id"] == item_ref:
                return item
    return None


def _find_phase_for_item(data, checklist_type, item_ref):
    cl = data.get("checklists", {}).get(checklist_type)
    if not cl:
        return None
    for phase in cl.get("phases", []):
        for item in phase.get("items", []):
            if item["id"] == item_ref:
                return phase
    return None


@checklists_bp.before_request
def _guard():
    require_dashboard_access()


# ---------------------------------------------------------------------------
# Overview page
# ---------------------------------------------------------------------------

@checklists_bp.route("/dashboard/checklists", methods=["GET"])
def checklists_overview():
    checklists = db_checklist.query.order_by(db_checklist.created_at.desc()).all()
    total_items = 0
    done_items = 0
    for cl in checklists:
        total_items += len(cl.items)
        done_items += sum(1 for i in cl.items if i.status in ("pass", "fail", "warn", "na"))

    data = _load_templates()
    type_cards = {}
    for ctype, info in CHECKLIST_TYPE_INFO.items():
        tpl = data.get("checklists", {}).get(ctype, {})
        phases = tpl.get("phases", [])
        type_cards[ctype] = {
            **info,
            "title": tpl.get("title", ctype),
            "phase_count": len(phases),
            "item_count": sum(len(p.get("items", [])) for p in phases),
            "phases": [p["title"] for p in phases],
        }

    return render_template(
        "checklists_overview.html",
        checklists=checklists,
        total_items=total_items,
        done_items=done_items,
        type_cards=type_cards,
        scope_targets=_get_scope_targets(),
    )


# ---------------------------------------------------------------------------
# Detail page
# ---------------------------------------------------------------------------

@checklists_bp.route("/dashboard/checklists/<int:checklist_id>", methods=["GET"])
def checklist_detail(checklist_id):
    cl = db.get_or_404(db_checklist, checklist_id)
    data = _load_templates()
    template = data.get("checklists", {}).get(cl.checklist_type, {})

    item_map = {i.item_ref: i for i in cl.items}

    # Pre-load linked finding statuses in bulk
    finding_ids = [i.finding_id for i in cl.items if i.finding_id]
    finding_status_map = {}
    if finding_ids:
        findings = db_bevindingen.query.filter(
            db_bevindingen.id.in_(finding_ids)
        ).all()
        finding_status_map = {
            f.id: {"status": f.status or "draft", "naam": f.naam, "basescore": f.basescore or ""}
            for f in findings
        }

    phases = []
    for phase in template.get("phases", []):
        phase_items = []
        total_in_phase = len(phase.get("items", []))
        for idx, tpl_item in enumerate(phase.get("items", []), 1):
            db_item = item_map.get(tpl_item["id"])
            finding_id = db_item.finding_id if db_item else None
            finding_info = finding_status_map.get(finding_id) if finding_id else None
            phase_items.append({
                "tpl": tpl_item,
                "db": db_item,
                "status": db_item.status if db_item else "open",
                "notitie": db_item.notitie if db_item else "",
                "note_id": db_item.note_id if db_item else None,
                "finding_id": finding_id,
                "finding_info": finding_info,
                "num": idx,
                "total": total_in_phase,
            })
        phases.append({
            "id": phase["id"],
            "title": phase["title"],
            "description": PHASE_DESCRIPTIONS.get(phase["id"], ""),
            "entries": phase_items,
        })

    return render_template(
        "checklist_detail.html",
        checklist=cl,
        phases=phases,
        template=template,
        scope_targets=_get_scope_targets(),
    )


# ---------------------------------------------------------------------------
# API: Create checklist
# ---------------------------------------------------------------------------

@checklists_bp.route("/api/checklists", methods=["POST"])
def create_checklist():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"ok": False, "error": "geen JSON body"}), 400

    naam = (body.get("naam") or "").strip()
    checklist_type = (body.get("type") or "").strip()
    target = (body.get("target") or "").strip()

    if not naam:
        return jsonify({"ok": False, "error": "naam is verplicht"}), 400

    data = _load_templates()
    if checklist_type not in data.get("checklists", {}):
        return jsonify({"ok": False, "error": "ongeldig type"}), 400

    cl = db_checklist(naam=naam, checklist_type=checklist_type, target=target)
    db.session.add(cl)
    db.session.flush()

    template = data["checklists"][checklist_type]
    for phase in template.get("phases", []):
        for item in phase.get("items", []):
            db_item = db_checklist_item(
                checklist_id=cl.id,
                item_ref=item["id"],
                status="open",
            )
            db.session.add(db_item)

    db.session.commit()
    return jsonify({"ok": True, "id": cl.id, "naam": cl.naam})


# ---------------------------------------------------------------------------
# API: Delete checklist
# ---------------------------------------------------------------------------

@checklists_bp.route("/api/checklists/<int:checklist_id>", methods=["DELETE"])
def delete_checklist(checklist_id):
    cl = db.session.get(db_checklist, checklist_id)
    if not cl:
        return jsonify({"ok": False, "error": "niet gevonden"}), 404
    db.session.delete(cl)
    db.session.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# API: Update item status
# ---------------------------------------------------------------------------

_VALID_ITEM_STATUSES = {"open", "pass", "fail", "warn", "skip", "na"}


@checklists_bp.route(
    "/api/checklists/<int:checklist_id>/items/<item_ref>/status", methods=["POST"]
)
def update_item_status(checklist_id, item_ref):
    cl = db.session.get(db_checklist, checklist_id)
    if not cl:
        return jsonify({"ok": False, "error": "checklist niet gevonden"}), 404

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"ok": False, "error": "geen JSON body"}), 400

    new_status = (body.get("status") or "").strip()
    if new_status not in _VALID_ITEM_STATUSES:
        return jsonify({"ok": False, "error": "ongeldige status"}), 400

    item = db_checklist_item.query.filter_by(
        checklist_id=checklist_id, item_ref=item_ref
    ).first()
    if not item:
        return jsonify({"ok": False, "error": "item niet gevonden"}), 404

    item.status = new_status
    cl.updated_at = datetime.datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "status": item.status})


# ---------------------------------------------------------------------------
# API: Inline notitie opslaan
# ---------------------------------------------------------------------------

@checklists_bp.route(
    "/api/checklists/<int:checklist_id>/items/<item_ref>/note", methods=["POST"]
)
def save_inline_note(checklist_id, item_ref):
    cl = db.session.get(db_checklist, checklist_id)
    if not cl:
        return jsonify({"ok": False, "error": "checklist niet gevonden"}), 404

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"ok": False, "error": "geen JSON body"}), 400

    item = db_checklist_item.query.filter_by(
        checklist_id=checklist_id, item_ref=item_ref
    ).first()
    if not item:
        return jsonify({"ok": False, "error": "item niet gevonden"}), 404

    item.notitie = (body.get("notitie") or "").strip()
    db.session.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# API: Create db_notes from checklist item
# ---------------------------------------------------------------------------

@checklists_bp.route(
    "/api/checklists/<int:checklist_id>/items/<item_ref>/create-note", methods=["POST"]
)
def create_note_from_item(checklist_id, item_ref):
    cl = db.session.get(db_checklist, checklist_id)
    if not cl:
        return jsonify({"ok": False, "error": "checklist niet gevonden"}), 404

    item = db_checklist_item.query.filter_by(
        checklist_id=checklist_id, item_ref=item_ref
    ).first()
    if not item:
        return jsonify({"ok": False, "error": "item niet gevonden"}), 404

    data = _load_templates()
    tpl_item = _find_item_in_template(data, cl.checklist_type, item_ref)

    naam = "[{}] {}".format(cl.naam, tpl_item["title"] if tpl_item else item_ref)
    parts = []
    if tpl_item:
        parts.append(tpl_item.get("description", ""))
    if item.notitie:
        parts.append("\n--- Inline notitie ---\n" + item.notitie)
    if tpl_item and tpl_item.get("commands"):
        parts.append("\n--- Commando's ---\n" + "\n".join(tpl_item["commands"]))

    note = db_notes(naam=naam, uitwerken="\n".join(parts).strip())
    db.session.add(note)
    db.session.flush()

    item.note_id = note.id
    db.session.commit()
    return jsonify({"ok": True, "note_id": note.id, "naam": note.naam})


# ---------------------------------------------------------------------------
# API: Create db_bevindingen from checklist item
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# API: Matching finding templates for a checklist item
# ---------------------------------------------------------------------------

@checklists_bp.route(
    "/api/checklists/<int:checklist_id>/items/<item_ref>/matching-templates",
    methods=["GET"],
)
def matching_templates(checklist_id, item_ref):
    cl = db.session.get(db_checklist, checklist_id)
    if not cl:
        return jsonify({"ok": False, "error": "checklist niet gevonden"}), 404

    data = _load_templates()
    tpl_item = _find_item_in_template(data, cl.checklist_type, item_ref)
    if not tpl_item:
        return jsonify({"ok": True, "templates": [], "finding_refs": []})

    finding_refs = tpl_item.get("finding_refs", [])
    matches = []
    seen_ids = set()
    for ref_title in finding_refs:
        results = db_bevindingen_templates.query.filter(
            db_bevindingen_templates.titel.ilike("%" + ref_title + "%")
        ).all()
        for tmpl in results:
            if tmpl.id not in seen_ids:
                seen_ids.add(tmpl.id)
                matches.append({
                    "id": tmpl.id,
                    "titel": tmpl.titel,
                    "bevtype": tmpl.bevtype or "",
                    "owasp": tmpl.owasp or "",
                    "basescore": tmpl.basescore or "",
                    "cvss": tmpl.cvss or "",
                    "matched_ref": ref_title,
                })

    return jsonify({
        "ok": True,
        "templates": matches,
        "finding_refs": finding_refs,
    })


# ---------------------------------------------------------------------------
# API: Create db_bevindingen from checklist item
# ---------------------------------------------------------------------------

@checklists_bp.route(
    "/api/checklists/<int:checklist_id>/items/<item_ref>/create-finding",
    methods=["POST"],
)
def create_finding_from_item(checklist_id, item_ref):
    cl = db.session.get(db_checklist, checklist_id)
    if not cl:
        return jsonify({"ok": False, "error": "checklist niet gevonden"}), 404

    item = db_checklist_item.query.filter_by(
        checklist_id=checklist_id, item_ref=item_ref
    ).first()
    if not item:
        return jsonify({"ok": False, "error": "item niet gevonden"}), 404

    body = request.get_json(silent=True) or {}
    requested_template_id = body.get("template_id")

    data = _load_templates()
    tpl_item = _find_item_in_template(data, cl.checklist_type, item_ref)

    # Zoek matching template — gebruik expliciet gevraagde of val terug op auto-match
    tmpl = None
    if requested_template_id:
        tmpl = db.session.get(db_bevindingen_templates, requested_template_id)

    if not tmpl and tpl_item and tpl_item.get("finding_refs"):
        for ref_title in tpl_item["finding_refs"]:
            tmpl = db_bevindingen_templates.query.filter(
                db_bevindingen_templates.titel.ilike("%" + ref_title + "%")
            ).first()
            if tmpl:
                break

    naam = tpl_item["title"] if tpl_item else item_ref
    bev = db_bevindingen(
        naam=tmpl.titel if tmpl else naam,
        ref=str(tmpl.id) if tmpl else "",
        locatie=cl.target or "",
        status="draft",
    )

    # Pre-populeer vanuit template als beschikbaar
    if tmpl:
        bev.invoegen = tmpl.nlbeschrijving or tmpl.enbeschrijving or ""
        bev.basescore = tmpl.basescore or ""
        bev.cvss = tmpl.cvss or ""

    # Voeg inline notitie toe als evidence
    if item.notitie:
        bev.uitwerken = item.notitie

    db.session.add(bev)
    db.session.flush()

    item.finding_id = bev.id
    db.session.commit()
    return jsonify({
        "ok": True,
        "finding_id": bev.id,
        "naam": bev.naam,
        "status": bev.status or "draft",
        "basescore": bev.basescore or "",
        "template_used": tmpl.titel if tmpl else "",
    })
