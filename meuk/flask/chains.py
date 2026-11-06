"""Exploit chain-visualisatie — aanvalspaden uit gekoppelde bevindingen.

Gebruikt de bestaande 'chain'-relaties (db_finding_related, relation_type='chain')
waarbij een kant finding_id -> related_id betekent: stap N leidt tot stap N+1.
Levert knopen, kanten en gelineariseerde paden voor zowel het dashboard als het
kill-chain-diagram in het rapport.
"""

from flask import Blueprint, jsonify, render_template

from meuk.flask.models import db_bevindingen, db_finding_related
from meuk.flask.findings import _cvss_to_severity, _active_findings
from meuk.flask.security import require_dashboard_access

chains_bp = Blueprint('chains_bp', __name__, template_folder='html')


@chains_bp.before_request
def _check_dashboard_access():
    require_dashboard_access()


def build_chains():
    """Bouw de chain-graaf: knopen, gerichte kanten en gelineariseerde paden.

    Returns dict met 'nodes', 'edges' en 'paths' (lijst van geordende id-lijsten).
    """
    # Alle chain-kanten tussen niet-verwijderde bevindingen
    actieve_ids = {b.id for b in _active_findings().all()}
    edges = []
    edge_relation_id = {}  # (van, naar) -> db_finding_related.id (eerste match)
    for r in db_finding_related.query.filter_by(relation_type='chain').all():
        if r.finding_id in actieve_ids and r.related_id in actieve_ids:
            edges.append((r.finding_id, r.related_id))
            edge_relation_id.setdefault((r.finding_id, r.related_id), r.id)
    edges = list(dict.fromkeys(edges))  # dedup, volgorde behouden

    # Betrokken knopen
    node_ids = set()
    for a, b in edges:
        node_ids.add(a)
        node_ids.add(b)
    nodes = []
    bevs = {b.id: b for b in db_bevindingen.query.filter(db_bevindingen.id.in_(node_ids)).all()} if node_ids else {}
    for nid in node_ids:
        b = bevs.get(nid)
        sev, _ = _cvss_to_severity(b.basescore if b else '0')
        nodes.append({'id': nid, 'naam': (b.naam if b else '') or '', 'severity': sev})

    # Lineariseer paden: start bij bronnen (geen inkomende kant), DFS langs uitgaande
    outgoing = {}
    incoming = set()
    for a, b in edges:
        outgoing.setdefault(a, []).append(b)
        incoming.add(b)
    sources = [n for n in node_ids if n not in incoming]
    if not sources:
        sources = sorted(node_ids)[:1]  # cyclus: kies een startpunt

    paths = []

    def _walk(start):
        path = [start]
        seen = {start}
        cur = start
        while cur in outgoing:
            nxt = None
            for cand in outgoing[cur]:
                if cand not in seen:
                    nxt = cand
                    break
            if nxt is None:
                break
            path.append(nxt)
            seen.add(nxt)
            cur = nxt
        return path

    for s in sorted(sources):
        paths.append(_walk(s))

    return {
        'nodes': nodes,
        'edges': [{'from': a, 'to': b, 'relation_id': edge_relation_id.get((a, b))}
                  for a, b in edges],
        'paths': paths,
    }


@chains_bp.route('/dashboard/chains', methods=['GET'])
def chains_dashboard():
    return render_template('chains.html')


@chains_bp.route('/api/findings/chains', methods=['GET'])
def api_chains():
    return jsonify(build_chains())
