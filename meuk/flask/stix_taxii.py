"""STIX 2.1 bundle builder + TAXII 2.1 read-only collection server."""

import datetime
import uuid

from flask import Blueprint, jsonify
from meuk.flask.models import db_bevindingen, db_bevindingen_templates
from meuk.flask.findings import _cvss_to_severity, _OWASP_CODES, owasptop10
from meuk.flask.security import require_dashboard_access

stix_taxii_bp = Blueprint('stix_taxii_bp', __name__)

# Deterministic UUID namespace for STIX objects
_IB_NS = uuid.UUID('a1b2c3d4-e5f6-7890-abcd-ef1234567890')

# Fixed collection ID (deterministic)
_COLLECTION_ID = str(uuid.uuid5(_IB_NS, 'ib:collection:findings'))


def _stix_id(obj_type, unique_key):
    """Generate a deterministic STIX 2.1 identifier."""
    return '{}--{}'.format(obj_type, uuid.uuid5(_IB_NS, 'ib:{}:{}'.format(obj_type, unique_key)))


def _now_stix():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')


def build_stix_bundle(findings_data, template_map, titel='', auteur=''):
    """Build a STIX 2.1 Bundle from finding data.

    Parameters
    ----------
    findings_data : list[db_bevindingen]
        Final findings from the database.
    template_map : dict[str, db_bevindingen_templates]
        Map of template id (str) -> template object.
    titel : str
        Project/rapport title.
    auteur : str
        Author / organisation name.

    Returns
    -------
    dict
        STIX 2.1 Bundle as a Python dict.
    """
    now = _now_stix()
    objects = []

    # 1. Identity SDO (author/organisation)
    identity_id = _stix_id('identity', auteur or 'ib')
    objects.append({
        'type': 'identity',
        'spec_version': '2.1',
        'id': identity_id,
        'created': now,
        'modified': now,
        'name': auteur or 'Incompetent Bastard',
        'identity_class': 'organization',
    })

    seen_attack_patterns = {}
    seen_infra = {}

    for bev in findings_data:
        tmpl = template_map.get(str(bev.ref))

        basescore = bev.basescore or (tmpl.basescore if tmpl else '') or '0'
        severity, _ = _cvss_to_severity(basescore)

        # 2. Vulnerability SDO
        vuln_id = _stix_id('vulnerability', str(bev.id))
        ext_refs = []

        # CWE
        if tmpl and tmpl.cwe:
            try:
                cwe_id = int(tmpl.cwe)
                ext_refs.append({
                    'source_name': 'cwe',
                    'external_id': 'CWE-{}'.format(cwe_id),
                    'url': 'https://cwe.mitre.org/data/definitions/{}.html'.format(cwe_id),
                })
            except (ValueError, TypeError):
                pass

        # OWASP
        if tmpl and tmpl.owasp:
            try:
                num = int(tmpl.owasp)
                code = _OWASP_CODES.get(num, 'A{:02d}'.format(num))
                label = owasptop10[num - 1] if 1 <= num <= 10 else code
                ext_refs.append({
                    'source_name': 'owasp',
                    'external_id': code,
                    'description': label,
                })
            except (ValueError, TypeError):
                pass

        # CVSS
        cvss_vector = bev.cvss or (tmpl.cvss if tmpl else '') or ''
        if basescore and basescore != '0':
            ref = {'source_name': 'cvss', 'description': 'CVSS {}'.format(basescore)}
            if cvss_vector:
                ref['url'] = cvss_vector
            ext_refs.append(ref)

        vuln_obj = {
            'type': 'vulnerability',
            'spec_version': '2.1',
            'id': vuln_id,
            'created': now,
            'modified': now,
            'name': bev.naam or 'Finding {}'.format(bev.id),
            'description': (tmpl.enbeschrijving or tmpl.nlbeschrijving or '') if tmpl else '',
            'created_by_ref': identity_id,
        }
        if ext_refs:
            vuln_obj['external_references'] = ext_refs

        objects.append(vuln_obj)

        # 3. Attack Pattern SDO (MITRE ATT&CK)
        if tmpl and tmpl.mitre:
            mitre_id = tmpl.mitre.strip()
            if mitre_id and mitre_id not in seen_attack_patterns:
                ap_id = _stix_id('attack-pattern', mitre_id)
                seen_attack_patterns[mitre_id] = ap_id
                objects.append({
                    'type': 'attack-pattern',
                    'spec_version': '2.1',
                    'id': ap_id,
                    'created': now,
                    'modified': now,
                    'name': mitre_id,
                    'external_references': [{
                        'source_name': 'mitre-attack',
                        'external_id': mitre_id,
                        'url': 'https://attack.mitre.org/techniques/{}/'.format(
                            mitre_id.replace('.', '/')),
                    }],
                })

            if mitre_id in seen_attack_patterns:
                # Relationship: vulnerability exploits attack-pattern
                objects.append({
                    'type': 'relationship',
                    'spec_version': '2.1',
                    'id': _stix_id('relationship', 'exploits:{}:{}'.format(bev.id, mitre_id)),
                    'created': now,
                    'modified': now,
                    'relationship_type': 'exploits',
                    'source_ref': vuln_id,
                    'target_ref': seen_attack_patterns[mitre_id],
                })

        # 4. Infrastructure SDO (host/location)
        host = (bev.locatie or '').strip()
        if host:
            if host not in seen_infra:
                infra_id = _stix_id('infrastructure', host)
                seen_infra[host] = infra_id
                objects.append({
                    'type': 'infrastructure',
                    'spec_version': '2.1',
                    'id': infra_id,
                    'created': now,
                    'modified': now,
                    'name': host,
                    'infrastructure_types': ['unknown'],
                })

            # Relationship: vulnerability targets infrastructure
            objects.append({
                'type': 'relationship',
                'spec_version': '2.1',
                'id': _stix_id('relationship', 'targets:{}:{}'.format(bev.id, host)),
                'created': now,
                'modified': now,
                'relationship_type': 'targets',
                'source_ref': vuln_id,
                'target_ref': seen_infra[host],
            })

    bundle = {
        'type': 'bundle',
        'id': _stix_id('bundle', titel or 'ib'),
        'objects': objects,
    }
    return bundle


# ---------------------------------------------------------------------------
# TAXII 2.1 read-only endpoints
# ---------------------------------------------------------------------------

_TAXII_CT = 'application/taxii+json;version=2.1'


def _taxii_response(data, status=200):
    resp = jsonify(data)
    resp.status_code = status
    resp.headers['Content-Type'] = _TAXII_CT
    return resp


@stix_taxii_bp.before_request
def _check_taxii_access():
    require_dashboard_access()


@stix_taxii_bp.route('/taxii2/', methods=['GET'])
def taxii_discovery():
    """TAXII 2.1 Discovery endpoint."""
    return _taxii_response({
        'title': 'Incompetent Bastard TAXII Server',
        'description': 'Read-only TAXII 2.1 server for pentest findings',
        'default': '/taxii2/',
    })


@stix_taxii_bp.route('/taxii2/collections/', methods=['GET'])
def taxii_collections():
    """TAXII 2.1 Collections endpoint."""
    return _taxii_response({
        'collections': [_collection_info()],
    })


@stix_taxii_bp.route('/taxii2/collections/findings/', methods=['GET'])
def taxii_collection_info():
    """TAXII 2.1 single Collection info."""
    return _taxii_response(_collection_info())


@stix_taxii_bp.route('/taxii2/collections/findings/objects/', methods=['GET'])
def taxii_collection_objects():
    """TAXII 2.1 Objects endpoint — returns STIX envelope with all final findings."""
    findings = db_bevindingen.query.filter_by(status='final').all()
    templates = db_bevindingen_templates.query.all()
    template_map = {str(t.id): t for t in templates}

    from meuk.flask.findings import _get_appdata
    s = _get_appdata()
    titel = (s.rapport_titel if s else '') or 'Penetration Test'
    auteur = (s.rapport_auteur if s else '') or 'Incompetent Bastard'

    bundle = build_stix_bundle(findings, template_map, titel=titel, auteur=auteur)

    envelope = {
        'more': False,
        'objects': bundle.get('objects', []),
    }
    return _taxii_response(envelope)


def _collection_info():
    return {
        'id': _COLLECTION_ID,
        'title': 'Pentest Findings',
        'description': 'STIX 2.1 objects generated from pentest findings',
        'can_read': True,
        'can_write': False,
        'media_types': [_TAXII_CT],
    }
