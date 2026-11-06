"""Exploration-graaf — handmatige aanvalsketen-modeler (ARTEX-stijl).

Knooptypen: start/goal/intent/fact/vulnerability/hint.
Getypeerde kanten: derive/intent_chain/produce/prove.
Een vulnerability-knoop kan naar een bestaande bevinding (db_bevindingen) wijzen.
"""

from flask import Blueprint, jsonify, render_template, request, current_app

from meuk.flask.models import (
    db, db_explore_node, db_explore_edge, db_bevindingen,
    db_asset, db_explore_asset_anchor,
)
from meuk.flask.findings import _cvss_to_severity, _log_change
from meuk.flask.security import require_dashboard_access

explore_bp = Blueprint('explore_bp', __name__, template_folder='html')

_NODE_TYPES = {'start', 'goal', 'intent', 'fact', 'vulnerability', 'hint'}
_EDGE_TYPES = {'derive', 'intent_chain', 'produce', 'prove'}
_STATUSES = {'pending', 'in_progress', 'done', 'achieved'}


@explore_bp.before_request
def _check_dashboard_access():
    require_dashboard_access()


def _csrf_ok():
    if not current_app.config.get('WTF_CSRF_ENABLED', True):
        return True
    from flask_wtf.csrf import validate_csrf
    try:
        validate_csrf(request.headers.get('X-CSRFToken', ''))
        return True
    except Exception:
        return False


def _depths(node_ids, edges):
    """Longest-path-diepte per knoop (bronnen=0), met cyclusbescherming."""
    depth = {nid: 0 for nid in node_ids}
    # Iteratieve relaxatie (begrensd op aantal knopen om een cyclus af te breken)
    for _ in range(len(node_ids)):
        changed = False
        for e in edges:
            if e['from'] in depth and e['to'] in depth and depth[e['to']] < depth[e['from']] + 1:
                depth[e['to']] = depth[e['from']] + 1
                changed = True
        if not changed:
            break
    return depth


def build_explore_graph(opdracht_id=None):
    q = db_explore_node.query
    if opdracht_id:
        q = q.filter(db_explore_node.opdracht_id == opdracht_id)
    nodes = q.order_by(db_explore_node.id).all()
    node_ids = {n.id for n in nodes}

    edge_rows = db_explore_edge.query.all()
    edges = [{'id': e.id, 'from': e.from_node, 'to': e.to_node, 'type': e.edge_type}
             for e in edge_rows if e.from_node in node_ids and e.to_node in node_ids]

    depth = _depths(node_ids, edges)

    bev_ids = {n.finding_id for n in nodes if n.finding_id}
    bevs = {b.id: b for b in db_bevindingen.query.filter(
        db_bevindingen.id.in_(bev_ids)).all()} if bev_ids else {}

    # Gekoppelde assets per knoop
    amap = {}
    if node_ids:
        ex_anchors = db_explore_asset_anchor.query.filter(
            db_explore_asset_anchor.node_id.in_(node_ids)).all()
        aids = {ea.asset_id for ea in ex_anchors}
        assets = {a.id: a for a in db_asset.query.filter(
            db_asset.id.in_(aids)).all()} if aids else {}
        for ea in ex_anchors:
            a = assets.get(ea.asset_id)
            if a:
                amap.setdefault(ea.node_id, []).append(
                    {'anchor_id': ea.id, 'asset_id': a.id, 'label': a.waarde})

    out_nodes = []
    for n in nodes:
        b = bevs.get(n.finding_id) if n.finding_id else None
        sev = None
        if b is not None:
            sev, _ = _cvss_to_severity(b.basescore)
        out_nodes.append({
            'id': n.id,
            'type': n.node_type,
            'titel': n.titel,
            'omschrijving': n.omschrijving or '',
            'status': n.status or 'pending',
            'prioriteit': n.prioriteit if n.prioriteit is not None else 5,
            'finding_id': n.finding_id,
            'finding_naam': (b.naam if b else None),
            'severity': sev,
            'retest': (getattr(b, 'retest_status', None) if b else None),
            'assets': amap.get(n.id, []),
            'depth': depth.get(n.id, 0),
        })
    return {'nodes': out_nodes, 'edges': edges}


@explore_bp.route('/dashboard/explore', methods=['GET'])
def explore_dashboard():
    return render_template('explore_graph.html', title='Exploration — aanvalsketen')


@explore_bp.route('/api/explore/graph', methods=['GET'])
def api_explore_graph():
    opdracht_id = request.args.get('opdracht_id', type=int)
    return jsonify(build_explore_graph(opdracht_id))


@explore_bp.route('/api/explore/nodes', methods=['POST'])
def create_node():
    if not _csrf_ok():
        return jsonify({'error': 'CSRF-fout'}), 403
    data = request.get_json(silent=True) or {}
    titel = (data.get('titel') or '').strip()
    if not titel:
        return jsonify({'error': 'titel is verplicht'}), 400
    node_type = (data.get('node_type') or 'intent').strip().lower()
    if node_type not in _NODE_TYPES:
        return jsonify({'error': 'ongeldig knooptype'}), 400
    try:
        prioriteit = int(data.get('prioriteit', 5))
    except (TypeError, ValueError):
        prioriteit = 5
    prioriteit = max(0, min(9, prioriteit))
    n = db_explore_node(
        titel=titel, node_type=node_type,
        omschrijving=(data.get('omschrijving') or '')[:5000],
        status=data.get('status') if data.get('status') in _STATUSES else 'pending',
        prioriteit=prioriteit,
        opdracht_id=data.get('opdracht_id') or None,
        finding_id=data.get('finding_id') or None,
    )
    db.session.add(n)
    db.session.commit()
    return jsonify({'ok': True, 'id': n.id})


@explore_bp.route('/api/explore/nodes/<int:node_id>', methods=['POST'])
def update_node(node_id):
    if not _csrf_ok():
        return jsonify({'error': 'CSRF-fout'}), 403
    n = db.session.get(db_explore_node, node_id)
    if not n:
        return jsonify({'error': 'knoop niet gevonden'}), 404
    data = request.get_json(silent=True) or {}
    if 'titel' in data and (data['titel'] or '').strip():
        n.titel = data['titel'].strip()[:255]
    if 'omschrijving' in data:
        n.omschrijving = str(data['omschrijving'])[:5000]
    if 'node_type' in data:
        if data['node_type'] not in _NODE_TYPES:
            return jsonify({'error': 'ongeldig knooptype'}), 400
        if n.node_type != data['node_type']:
            _log_change('db_explore_node', n.id, 'node_type', n.node_type, data['node_type'])
        n.node_type = data['node_type']
    if 'status' in data:
        if data['status'] not in _STATUSES:
            return jsonify({'error': 'ongeldige status'}), 400
        if n.status != data['status']:
            _log_change('db_explore_node', n.id, 'status', n.status, data['status'])
        n.status = data['status']
    if 'prioriteit' in data:
        try:
            nieuw = max(0, min(9, int(data['prioriteit'])))
        except (TypeError, ValueError):
            return jsonify({'error': 'ongeldige prioriteit'}), 400
        if n.prioriteit != nieuw:
            _log_change('db_explore_node', n.id, 'prioriteit', n.prioriteit, nieuw)
        n.prioriteit = nieuw
    if 'finding_id' in data:
        n.finding_id = data['finding_id'] or None
    db.session.commit()
    return jsonify({'ok': True})


@explore_bp.route('/api/explore/nodes/<int:node_id>', methods=['DELETE'])
def delete_node(node_id):
    if not _csrf_ok():
        return jsonify({'error': 'CSRF-fout'}), 403
    n = db.session.get(db_explore_node, node_id)
    if not n:
        return jsonify({'error': 'knoop niet gevonden'}), 404
    # Kanten van/naar deze knoop cascaden via de relaties
    db.session.delete(n)
    db.session.commit()
    return jsonify({'ok': True})


@explore_bp.route('/api/explore/edges', methods=['POST'])
def create_edge():
    if not _csrf_ok():
        return jsonify({'error': 'CSRF-fout'}), 403
    data = request.get_json(silent=True) or {}
    try:
        frm = int(data.get('from'))
        to = int(data.get('to'))
    except (TypeError, ValueError):
        return jsonify({'error': 'from en to zijn verplicht'}), 400
    if frm == to:
        return jsonify({'error': 'een knoop kan niet naar zichzelf wijzen'}), 400
    edge_type = (data.get('edge_type') or 'derive').strip().lower()
    if edge_type not in _EDGE_TYPES:
        return jsonify({'error': 'ongeldig kanttype'}), 400
    if not db.session.get(db_explore_node, frm) or not db.session.get(db_explore_node, to):
        return jsonify({'error': 'knoop niet gevonden'}), 404
    bestaat = db_explore_edge.query.filter_by(
        from_node=frm, to_node=to, edge_type=edge_type).first()
    if bestaat:
        return jsonify({'ok': True, 'id': bestaat.id})
    e = db_explore_edge(from_node=frm, to_node=to, edge_type=edge_type)
    db.session.add(e)
    db.session.commit()
    return jsonify({'ok': True, 'id': e.id})


@explore_bp.route('/api/explore/edges/<int:edge_id>', methods=['DELETE'])
def delete_edge(edge_id):
    if not _csrf_ok():
        return jsonify({'error': 'CSRF-fout'}), 403
    e = db.session.get(db_explore_edge, edge_id)
    if not e:
        return jsonify({'error': 'kant niet gevonden'}), 404
    db.session.delete(e)
    db.session.commit()
    return jsonify({'ok': True})


@explore_bp.route('/api/explore/import-chains', methods=['POST'])
def import_chains():
    """Importeer bestaande exploit-chains (db_finding_related type 'chain') als
    exploration-knopen (vulnerability, gekoppeld aan de bevinding) en -kanten."""
    if not _csrf_ok():
        return jsonify({'error': 'CSRF-fout'}), 403
    from meuk.flask.chains import build_chains
    data = request.get_json(silent=True) or {}
    opdracht_id = data.get('opdracht_id') or None
    g = build_chains()

    existing = {n.finding_id: n for n in db_explore_node.query.filter(
        db_explore_node.finding_id.isnot(None)).all()}
    node_for_fid = {}
    created_nodes = 0
    for gn in g.get('nodes', []):
        fid = gn['id']
        node = existing.get(fid)
        if node is None:
            node = db_explore_node(
                titel=gn.get('naam') or ('Bevinding #%d' % fid),
                node_type='vulnerability', finding_id=fid,
                status='pending', opdracht_id=opdracht_id)
            db.session.add(node)
            db.session.flush()
            existing[fid] = node
            created_nodes += 1
        node_for_fid[fid] = node

    created_edges = 0
    for e in g.get('edges', []):
        a = node_for_fid.get(e['from'])
        b = node_for_fid.get(e['to'])
        if not a or not b:
            continue
        dup = db_explore_edge.query.filter_by(
            from_node=a.id, to_node=b.id, edge_type='produce').first()
        if dup:
            continue
        db.session.add(db_explore_edge(from_node=a.id, to_node=b.id, edge_type='produce'))
        created_edges += 1
    db.session.commit()
    return jsonify({'ok': True, 'nodes': created_nodes, 'edges': created_edges})


@explore_bp.route('/api/explore/nodes/<int:node_id>/assets', methods=['POST'])
def anchor_asset(node_id):
    """Koppel een exploration-knoop aan een asset (ARTEX-anchor)."""
    if not _csrf_ok():
        return jsonify({'error': 'CSRF-fout'}), 403
    n = db.session.get(db_explore_node, node_id)
    if not n:
        return jsonify({'error': 'knoop niet gevonden'}), 404
    data = request.get_json(silent=True) or {}
    try:
        asset_id = int(data.get('asset_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'asset_id is verplicht'}), 400
    if not db.session.get(db_asset, asset_id):
        return jsonify({'error': 'asset niet gevonden'}), 404
    dup = db_explore_asset_anchor.query.filter_by(node_id=node_id, asset_id=asset_id).first()
    if dup:
        return jsonify({'ok': True, 'id': dup.id})
    ea = db_explore_asset_anchor(node_id=node_id, asset_id=asset_id)
    db.session.add(ea)
    db.session.commit()
    return jsonify({'ok': True, 'id': ea.id})


@explore_bp.route('/api/explore/assets/anchor/<int:anchor_id>', methods=['DELETE'])
def unanchor_asset(anchor_id):
    """Verwijder een node<->asset-anchor."""
    if not _csrf_ok():
        return jsonify({'error': 'CSRF-fout'}), 403
    ea = db.session.get(db_explore_asset_anchor, anchor_id)
    if not ea:
        return jsonify({'error': 'anchor niet gevonden'}), 404
    db.session.delete(ea)
    db.session.commit()
    return jsonify({'ok': True})
