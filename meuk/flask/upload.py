from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response

upload_bp = Blueprint('upload_bp', __name__,
                    template_folder='meuk/templates',
                    static_folder='meuk/static')


#handle uploads writes to raw loot, fetches the ip creates a folder and saves the file
@upload_bp.route("/upload", methods=["POST"])
@upload_bp.route("/upload/", methods=["POST"])
def meukuploads():
    #check_scope


    ip = request.remote_addr
    try:
        if not os.path.exists(os.path.join('raw', 'loot', ip)):
            os.makedirs(f"raw/loot/{ip}")
        file = request.files['file']
        file.save(os.path.join('raw', 'loot', ip, file.filename))
        return "[*] Incompetent Bastard v0.42\n[+] Tot ziens en bedankt voor de vis..."
    except:
        return  "[*] Incompetent Bastard v0.42\n[!] You failed! Try with curl -F file=@FILENAME http://127.0.0.1/upload"


@upload_bp.route("/uploadform", methods=["GET","POST"])
@upload_bp.route("/uploadform/", methods=["GET","POST"])
def meukupload():
    return 'ik ben het formulier'
