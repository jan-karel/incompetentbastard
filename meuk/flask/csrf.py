from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
import requests



csrf_bp = Blueprint('csrf_bp', __name__,
                    template_folder='html',
                    static_folder='static')



@csrf_bp.route("/csrf.js", methods=["GET", "POST"])
def csrf_js():
    pagina='''



    '''




    return pagina, 200, {
        'Content-Type': 'text/javascript',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }






@csrf_bp.route("/csrf/inject.html", methods=["GET", "POST"])
def csrf_pagina():
    pagina='''

    '''
    return pagina