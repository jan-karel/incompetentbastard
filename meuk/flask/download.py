from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
#from meuk.flask.models
#from meuk.flask.views


# Blueprint Configuration
download_bp = Blueprint('download_bp', __name__,
                    template_folder='templates',
                    static_folder='static')
#downloads
@download_bp.route("/p/<bestand>", methods=["GET"])
@download_bp.route("/payloads/<bestand>", methods=["GET"])
def payload_download(bestand):
    if os.path.isfile(os.path.join('http','payloads', bestand)):
        return send_from_directory('http/payloads/', bestand, as_attachment=True)
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#downloads
@download_bp.route("/t/<bestand>", methods=["GET"])
@download_bp.route("/tools/<bestand>", methods=["GET"])
def tools_download(bestand):
    if os.path.isfile(os.path.join('http','tools', bestand)):
        return send_from_directory('http/tools/', bestand, as_attachment=True)
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

@download_bp.route("/tm/<bestand>", methods=["GET"])
@download_bp.route("/tools/mini/<bestand>", methods=["GET"])
def mimi_download(bestand):
    if os.path.isfile(os.path.join('http','tools','mini', bestand)):
        return send_from_directory('http/tools/mini/', bestand, as_attachment=True)
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

'''
get files in base64




@download_bp.route("/tm/b64/<bestand>", methods=["GET"])
def mimi_download_b64(bestand):
    if os.path.isfile(os.path.join('http','tools','mini', bestand)):
        best = lezen(f"http/tools/mini/{bestand}")
        schrijven
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")


'''

#backend

@download_bp.route("/dashboard/bestanden", methods=["GET"])
@download_bp.route("/dashboard/bestanden/", methods=["GET"])
def dashboard_bestanden(bestand):
    if os.path.isfile(os.path.join('http','tools','mini', bestand)):
        return send_from_directory('http/tools/mini/', bestand, as_attachment=True)
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")


@download_bp.route("/dashboard/payloads", methods=["GET"])
@download_bp.route("/dashboard/payloads/", methods=["GET"])
def dashboard_payloads(bestand):
    if os.path.isfile(os.path.join('http','tools','mini', bestand)):
        return send_from_directory('http/tools/mini/', bestand, as_attachment=True)
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")
