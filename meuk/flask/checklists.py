"""Checklists blueprint — pentest checklist management."""

import datetime
import json
import os
import re

from flask import Blueprint, jsonify, render_template, request

from app import db
from meuk.flask.models import (
    db_bevindingen,
    db_bevindingen_templates,
    db_checklist,
    db_checklist_item,
    db_checklist_template,
    db_instellingen,
    db_notes,
    nu_utc,
)
from meuk.flask.security import require_dashboard_access


def _get_scope_targets():
    """Haal scope targets op uit de config van het actieve project."""
    from meuk.flask import project as _project
    cfg = _project.current_config()
    try:
        return json.loads(getattr(cfg, 'rapport_scope_targets', '[]') or '[]')
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
    # DigiD (NOREA Handreiking ICT-beveiligingsassessment DigiD 2026, Bijlage 6)
    "digid_org": "Organisatorische ingangscriteria: onafhankelijkheid, ervaring, instemmings- en vrijwaringsverklaring, beschikbaarheid, communicatie en planning.",
    "digid_scope": "Scope en normstelling: object van onderzoek, DigiD-subset van de NCSC-normen (aangevuld met OWASP/WASC/GHDB), greybox-benadering en formulierselectie.",
    "digid_verkenning": "Ingangscriteria verkenningsfase: inventarisatie webfacing infra, test gelijk aan productie, representatieve testdata, DigiD-testaccounts en applicatiekennis.",
    "digid_analyse": "Initiële kwetsbaarhedenanalyse: fingerprinting van merken/versies, inventarisatie van bekende kwetsbaarheden en selectie van tests.",
    "digid_auto": "Geautomatiseerde (dynamische) tests: toolkeuze en dekkingsgraad, afbakening tool versus handmatig, en bewaking tijdens uitvoering.",
    "digid_manual": "Handmatige tests: expertise, SSL/TLS en cookies, handmatige verificatie van auto-bevindingen, vervolgtesten en functionele flows.",
    "digid_norm": "Normdekking: de technische DigiD-normen (U/WA, U/PW, U/NW, U/TV, C.04, C.09) die met de pentest worden getoetst.",
    "digid_code": "Optionele code review (statisch testen), afhankelijk van de norm en bij twijfel over het gedrag van de applicatie.",
    "digid_prod": "Productieverificatie: vergelijk versie, SSL-configuratie, security-headers, container-versies en deployment-evidence tussen test en productie.",
    "digid_rapport": "Rapportage en afstemming: classificatie, afwijkingen en risico per norm, PoC's, aanbevelingen, versleutelde uitwisseling, hertest en archivering.",
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
    "digid": {
        "icon": "shield",
        "scope": "DigiD-webapplicatie, NOREA 2026 / Norm v3.0",
        "description": "Pentest-checklist voor het DigiD ICT-beveiligingsassessment, "
        "gebaseerd op de NOREA Handreiking 2026 (Bijlage 6) en de DigiD-normen "
        "(U/WA, U/PW, U/NW, U/TV, C.04, C.09).",
    },
}


def _load_builtin_templates():
    """De ingebouwde sjablonen uit het JSON-bestand (alleen-lezen)."""
    with open(_JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _custom_templates():
    """Eigen sjablonen uit de database → {type_key: {...}}.

    Faalt stil (lege dict) als er geen app-context of tabel is, zodat
    _load_templates() ook buiten een request bruikbaar blijft.
    """
    out = {}
    try:
        rows = db_checklist_template.query.all()
    except Exception:
        return out
    for row in rows:
        try:
            phases = json.loads(row.data or "{}").get("phases", [])
        except (json.JSONDecodeError, TypeError):
            phases = []
        out[row.type_key] = {
            "title": row.title,
            "phases": phases,
            "icon": row.icon or "list",
            "scope": row.scope or "",
            "description": row.description or "",
            "builtin": False,
        }
    return out


def _load_templates():
    """Samengevoegde sjablonen: ingebouwd (JSON) + eigen (DB).

    Vorm blijft {"checklists": {type_key: {title, phases, icon, scope,
    description, builtin}}}, zodat alle bestaande aanroepers (incl. het
    rapport) de eigen types automatisch meekrijgen.
    """
    data = _load_builtin_templates()
    checklists = data.get("checklists", {})
    for key, tpl in checklists.items():
        info = CHECKLIST_TYPE_INFO.get(key, {})
        tpl.setdefault("icon", info.get("icon", "list"))
        tpl.setdefault("scope", info.get("scope", ""))
        tpl.setdefault("description", info.get("description", ""))
        tpl["builtin"] = True
    for key, tpl in _custom_templates().items():
        if key not in checklists:  # ingebouwde namen hebben voorrang
            checklists[key] = tpl
    data["checklists"] = checklists
    return data


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
    from meuk.flask import project as _project
    checklists = _project.apply_scope(
        db_checklist.query, db_checklist.opdracht_id,
        _project.current_opdracht_id()
    ).order_by(db_checklist.created_at.desc()).all()
    total_items = 0
    done_items = 0
    for cl in checklists:
        total_items += len(cl.items)
        done_items += sum(1 for i in cl.items if i.status in ("pass", "fail", "warn", "na"))

    data = _load_templates()
    type_cards = {}
    for ctype, tpl in data.get("checklists", {}).items():
        phases = tpl.get("phases", [])
        type_cards[ctype] = {
            "icon": tpl.get("icon", "list"),
            "scope": tpl.get("scope", ""),
            "description": tpl.get("description", ""),
            "builtin": bool(tpl.get("builtin")),
            "type_key": ctype,
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
        # Template-item dat na het aanmaken van deze checklist is toegevoegd
        # (bijv. een nieuwe norm): maak de rij alsnog aan mits de ref in het
        # sjabloon bestaat. Zo blijven bestaande checklists meebewegen.
        if not _find_item_in_template(_load_templates(), cl.checklist_type, item_ref):
            return jsonify({"ok": False, "error": "item niet gevonden"}), 404
        item = db_checklist_item(checklist_id=checklist_id, item_ref=item_ref)
        db.session.add(item)

    item.status = new_status
    cl.updated_at = nu_utc()
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


# ===========================================================================
# Sjabloonbeheer: importeren / exporteren / aanmaken / bewerken
# ===========================================================================

_BUILTIN_KEYS = {"extern", "intern"}


def _slugify_key(s):
    """Maak een veilige, korte type_key van een string."""
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:16] or "custom"


def _unique_type_key(base):
    existing = set(_load_templates().get("checklists", {}).keys())
    key = base
    n = 2
    while key in existing:
        key = "%s-%d" % (base[:14], n)
        n += 1
    return key


def _validate_template_payload(body):
    """Valideer en normaliseer een sjabloon-payload.

    Retourneert (clean, None) of (None, foutmelding). ``clean`` bevat
    title/icon/scope/description/phases met opgeschoonde, unieke item-ids.
    """
    if not isinstance(body, dict):
        return None, "ongeldige JSON"
    title = (body.get("title") or "").strip()
    if not title:
        return None, "titel is verplicht"
    phases_in = body.get("phases")
    if not isinstance(phases_in, list) or not phases_in:
        return None, "minstens één fase is verplicht"
    phases = []
    seen_items = set()
    seen_phase_ids = set()
    for pi, p in enumerate(phases_in, 1):
        if not isinstance(p, dict):
            return None, "fase %d is ongeldig" % pi
        ptitle = (p.get("title") or "").strip()
        if not ptitle:
            return None, "fase %d mist een titel" % pi
        pid = _slugify_key(p.get("id") or "") or ("phase-%d" % pi)
        if pid in seen_phase_ids:
            pid = "%s-%d" % (pid[:12], pi)
        seen_phase_ids.add(pid)
        items_in = p.get("items") or []
        if not isinstance(items_in, list):
            return None, "fase '%s' heeft ongeldige items" % ptitle
        items = []
        for ii, it in enumerate(items_in, 1):
            if not isinstance(it, dict):
                return None, "een item in fase '%s' is ongeldig" % ptitle
            ititle = (it.get("title") or "").strip()
            if not ititle:
                return None, "een item in fase '%s' mist een titel" % ptitle
            iid = (it.get("id") or "").strip() or ("%s_%d" % (pid, ii))
            iid = iid[:64]
            if iid in seen_items:
                return None, "dubbel item-id: %s" % iid
            seen_items.add(iid)
            item = {"id": iid, "title": ititle}
            if (it.get("description") or "").strip():
                item["description"] = str(it["description"]).strip()
            cmds = it.get("commands")
            if isinstance(cmds, list):
                cmds = [str(c).strip() for c in cmds if str(c).strip()]
                if cmds:
                    item["commands"] = cmds
            refs = it.get("finding_refs")
            if isinstance(refs, list):
                refs = [str(r).strip() for r in refs if str(r).strip()]
                if refs:
                    item["finding_refs"] = refs
            items.append(item)
        phases.append({"id": pid, "title": ptitle, "items": items})
    return {
        "title": title[:255],
        "icon": (_slugify_key(body.get("icon") or "list") or "list")[:40],
        "scope": (body.get("scope") or "").strip()[:255],
        "description": (body.get("description") or "").strip(),
        "phases": phases,
    }, None


def _save_custom_template(type_key, clean):
    row = db_checklist_template.query.filter_by(type_key=type_key).first()
    if row is None:
        row = db_checklist_template(type_key=type_key)
        db.session.add(row)
    row.title = clean["title"]
    row.icon = clean["icon"]
    row.scope = clean["scope"]
    row.description = clean["description"]
    row.data = json.dumps({"phases": clean["phases"]}, ensure_ascii=False)
    return row


def _template_export_payload(type_key, tpl):
    return {
        "kind": "checklist-template",
        "version": 1,
        "type_key": type_key,
        "title": tpl.get("title", type_key),
        "icon": tpl.get("icon", "list"),
        "scope": tpl.get("scope", ""),
        "description": tpl.get("description", ""),
        "phases": tpl.get("phases", []),
    }


@checklists_bp.route("/api/checklists/templates", methods=["GET"])
def list_templates():
    out = []
    for key, tpl in _load_templates().get("checklists", {}).items():
        phases = tpl.get("phases", [])
        out.append({
            "type_key": key,
            "title": tpl.get("title", key),
            "icon": tpl.get("icon", "list"),
            "scope": tpl.get("scope", ""),
            "description": tpl.get("description", ""),
            "builtin": bool(tpl.get("builtin")),
            "phase_count": len(phases),
            "item_count": sum(len(p.get("items", [])) for p in phases),
        })
    return jsonify({"ok": True, "templates": out})


@checklists_bp.route("/api/checklists/templates/<type_key>/export", methods=["GET"])
def export_template(type_key):
    tpl = _load_templates().get("checklists", {}).get(type_key)
    if not tpl:
        return jsonify({"ok": False, "error": "onbekend type"}), 404
    resp = jsonify(_template_export_payload(type_key, tpl))
    resp.headers["Content-Disposition"] = (
        "attachment; filename=checklist-template-%s.json" % type_key)
    return resp


@checklists_bp.route("/api/checklists/templates", methods=["POST"])
def create_template():
    """Maak een eigen sjabloon (ook gebruikt door 'importeren': de UI post
    simpelweg de JSON uit het bestand hierheen)."""
    body = request.get_json(silent=True)
    clean, err = _validate_template_payload(body or {})
    if err:
        return jsonify({"ok": False, "error": err}), 400
    base = _slugify_key((body or {}).get("type_key") or clean["title"])
    if base in _BUILTIN_KEYS:
        base = base + "-eigen"
    type_key = _unique_type_key(base)
    _save_custom_template(type_key, clean)
    db.session.commit()
    return jsonify({
        "ok": True,
        "type_key": type_key,
        "title": clean["title"],
        "phase_count": len(clean["phases"]),
        "item_count": sum(len(p["items"]) for p in clean["phases"]),
    })


@checklists_bp.route("/api/checklists/templates/<type_key>", methods=["POST"])
def update_template(type_key):
    tpl = _load_templates().get("checklists", {}).get(type_key)
    if not tpl:
        return jsonify({"ok": False, "error": "onbekend type"}), 404
    if tpl.get("builtin"):
        return jsonify({"ok": False, "error":
                        "ingebouwde sjablonen zijn niet bewerkbaar; "
                        "dupliceer er een bewerkbare kopie van"}), 403
    body = request.get_json(silent=True)
    clean, err = _validate_template_payload(body or {})
    if err:
        return jsonify({"ok": False, "error": err}), 400
    _save_custom_template(type_key, clean)
    db.session.commit()
    return jsonify({"ok": True, "type_key": type_key, "title": clean["title"]})


@checklists_bp.route("/api/checklists/templates/<type_key>", methods=["DELETE"])
def delete_template(type_key):
    row = db_checklist_template.query.filter_by(type_key=type_key).first()
    if row is None:
        return jsonify({"ok": False, "error":
                        "onbekend of ingebouwd sjabloon"}), 404
    used = db_checklist.query.filter_by(checklist_type=type_key).count()
    if used:
        return jsonify({"ok": False, "error":
                        "%d checklist(s) gebruiken dit sjabloon; "
                        "verwijder die eerst" % used}), 409
    db.session.delete(row)
    db.session.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Sjabloon-editor (aanmaken / bewerken / dupliceren)
# ---------------------------------------------------------------------------

@checklists_bp.route("/dashboard/checklists/template/new", methods=["GET"])
def template_editor_new():
    initial = {"title": "", "icon": "list", "scope": "", "description": "",
               "phases": [{"id": "", "title": "", "items": []}]}
    src = request.args.get("from")
    if src:
        tpl = _load_templates().get("checklists", {}).get(src)
        if tpl:
            initial = {
                "title": tpl.get("title", "") + " (kopie)",
                "icon": tpl.get("icon", "list"),
                "scope": tpl.get("scope", ""),
                "description": tpl.get("description", ""),
                "phases": tpl.get("phases", []),
            }
    return render_template("checklist_template_editor.html",
                           mode="new", type_key="",
                           initial=initial)


@checklists_bp.route("/dashboard/checklists/template/<type_key>", methods=["GET"])
def template_editor_edit(type_key):
    tpl = _load_templates().get("checklists", {}).get(type_key)
    if not tpl:
        return render_template("checklist_template_editor.html",
                               mode="new", type_key="",
                               initial={"title": "", "icon": "list", "scope": "", "description": "", "phases": [{"id": "", "title": "", "items": []}]})
    if tpl.get("builtin"):
        # Ingebouwd: open als bewerkbare kopie i.p.v. direct bewerken.
        initial = {
            "title": tpl.get("title", "") + " (kopie)",
            "icon": tpl.get("icon", "list"),
            "scope": tpl.get("scope", ""),
            "description": tpl.get("description", ""),
            "phases": tpl.get("phases", []),
        }
        return render_template("checklist_template_editor.html",
                               mode="new", type_key="",
                               initial=initial)
    initial = {
        "title": tpl.get("title", ""),
        "icon": tpl.get("icon", "list"),
        "scope": tpl.get("scope", ""),
        "description": tpl.get("description", ""),
        "phases": tpl.get("phases", []),
    }
    return render_template("checklist_template_editor.html",
                           mode="edit", type_key=type_key,
                           initial=initial)


# ===========================================================================
# Ingevulde checklists: exporteren / importeren / bewerken
# ===========================================================================

@checklists_bp.route("/api/checklists/<int:checklist_id>/export", methods=["GET"])
def export_checklist(checklist_id):
    cl = db.session.get(db_checklist, checklist_id)
    if not cl:
        return jsonify({"ok": False, "error": "niet gevonden"}), 404
    tpl = _load_templates().get("checklists", {}).get(cl.checklist_type, {})
    payload = {
        "kind": "checklist-instance",
        "version": 1,
        "naam": cl.naam,
        "target": cl.target or "",
        "status": cl.status or "active",
        "checklist_type": cl.checklist_type,
        "template_snapshot": {
            "title": tpl.get("title", cl.checklist_type),
            "icon": tpl.get("icon", "list"),
            "scope": tpl.get("scope", ""),
            "description": tpl.get("description", ""),
            "phases": tpl.get("phases", []),
            "builtin": bool(tpl.get("builtin")),
        },
        "items": [
            {"item_ref": i.item_ref, "status": i.status or "open",
             "notitie": i.notitie or ""}
            for i in cl.items
        ],
    }
    resp = jsonify(payload)
    resp.headers["Content-Disposition"] = (
        "attachment; filename=checklist-%d.json" % cl.id)
    return resp


@checklists_bp.route("/api/checklists/import", methods=["POST"])
def import_checklist():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "ongeldige JSON"}), 400
    items_in = body.get("items")
    if not isinstance(items_in, list):
        return jsonify({"ok": False, "error": "items ontbreken in de export"}), 400

    naam = (body.get("naam") or "").strip() or "Geïmporteerde checklist"
    target = (body.get("target") or "").strip()
    checklist_type = (body.get("checklist_type") or "").strip()

    templates = _load_templates().get("checklists", {})
    if checklist_type not in templates:
        # Onbekend type: maak een eigen sjabloon uit de meegeleverde snapshot.
        snap = body.get("template_snapshot")
        clean, err = _validate_template_payload(snap or {})
        if err:
            return jsonify({"ok": False, "error":
                            "onbekend type en geen bruikbare "
                            "template_snapshot: %s" % err}), 400
        base = _slugify_key(checklist_type or clean["title"])
        if base in _BUILTIN_KEYS:
            base = base + "-eigen"
        checklist_type = _unique_type_key(base)
        _save_custom_template(checklist_type, clean)
        db.session.flush()

    cl = db_checklist(naam=naam, checklist_type=checklist_type, target=target,
                      status=(body.get("status") or "active").strip() or "active")
    db.session.add(cl)
    db.session.flush()
    for it in items_in:
        if not isinstance(it, dict):
            continue
        ref = (it.get("item_ref") or "").strip()
        if not ref:
            continue
        st = (it.get("status") or "open").strip()
        if st not in _VALID_ITEM_STATUSES:
            st = "open"
        db.session.add(db_checklist_item(
            checklist_id=cl.id, item_ref=ref[:64], status=st,
            notitie=(it.get("notitie") or "")))
    db.session.commit()
    return jsonify({"ok": True, "id": cl.id, "naam": cl.naam,
                    "checklist_type": checklist_type})


@checklists_bp.route("/api/checklists/<int:checklist_id>", methods=["POST"])
def update_checklist(checklist_id):
    cl = db.session.get(db_checklist, checklist_id)
    if not cl:
        return jsonify({"ok": False, "error": "niet gevonden"}), 404
    body = request.get_json(silent=True) or {}
    if "naam" in body:
        naam = (body.get("naam") or "").strip()
        if not naam:
            return jsonify({"ok": False, "error": "naam mag niet leeg zijn"}), 400
        cl.naam = naam[:255]
    if "target" in body:
        cl.target = (body.get("target") or "").strip()[:255]
    if "status" in body:
        cl.status = (body.get("status") or "active").strip()[:16] or "active"
    cl.updated_at = nu_utc()
    db.session.commit()
    return jsonify({"ok": True, "naam": cl.naam, "target": cl.target,
                    "status": cl.status})
