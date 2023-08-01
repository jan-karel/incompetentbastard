from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
from meuk.flask.models import *
import glob

# Blueprint Configuration
index_bp = Blueprint('index_bp', __name__,
                    template_folder='html',
                    static_folder='static')


#basic website
@index_bp.route('/', defaults={'cms_pag': 'index'}, methods=['GET', 'POST'])
@index_bp.route('/<cms_pag>')
def index(cms_pag):
    ip = request.remote_addr
    if ip != '127.0.0.1':

        #setup our payload delivery

        #is payload accepted
        

        return '<html><title>hallo wereld</title><body><h1>Een moment a.u.b.</h1><script type="application/javascript" src="/x.js"</body></html>'

    else:
        #use our normal pages
        return '<html><body>noppers, wacht op de volgende updare</html></body>'

#favicon
@index_bp.route('/favicon.ico')
def favicon():
    return ''