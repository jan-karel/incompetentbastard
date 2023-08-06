from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
import requests



sqli2_bp = Blueprint('sqli2_bp', __name__,
                    template_folder='html',
                    static_folder='static')


@sqli2_bp.route("/sqli2/inject", methods=["GET", "POST"])
def sqli2_pagina():

    if request.args.get('sql'):
        #request1


        #request2


        #resp

        return 'response'
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")




@sqli2_bp.route("/sqli2/injectshell", methods=["GET", "POST"])
def sqli2_injectshell():

    if request.args.get('sql'):
        '''MSSQL

        

         PostgreSQL


         ORACLE

    


        '''


        #request2


        #resp

        return 'response'
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")






@sqli2_bp.route("/sqli2/handmatig", methods=["GET", "POST"])
def sqli2_handmatig():

    if request.args.get('sql'):
        '''
        wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -d "db=mysql&id=FUZZ" -u http://yolo/api/intro

        
        MSSQL
        select @@version;
        SELECT SYSTEM_USER;
        SELECT name FROM sys.databases;
        select * from app.information_schema.tables;
        select COLUMN_NAME, DATA_TYPE from app.information_schema.columns where TABLE_NAME = 'menu';


         PostgreSQL
        select version();
        select current_user;
        select datname from pg_database;
        select table_name from app.information_schema.tables where table_schema ='public'
        select column_name, data_type from app.information_schema.columns where table_name = 'menu';

         ORACLE
        select * from v$version;
        select user from dual;
        select owner from all_tables group by owner;
    


        '''


        #request2


        #resp

        return 'response'
    else:
        abort(404, description="[*] Incompetent Bastard v0.42\n[!] You failed!")