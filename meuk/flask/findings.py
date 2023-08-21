from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
from meuk.flask.models import *
from meuk.flask.forms import *
import glob
import re
from sh import pandoc


appdata = db_instellingen.query.first()

# Blueprint Configuration
findings_bp = Blueprint('findings_bp', __name__,
                    template_folder='html',
                    static_folder='static')


#basic vars
htmlrefs =[]
owasptop10 = [
            ('A1 - Broken Access Control'),
            ('A2 - Crypthographic Failures'),
            ('A3 - Injection'),
            ('A4 - Insecure Design'),
            ('A5 - Security Misconfiguration'),
            ('A6 - Vulnerable and Outdated Components'),
            ('A7 - Identification and Authentication Failures'),
            ('A8 - Software and Data Integrity Failures'),
            ('A9 - Security Logging and Monitoring Failures'),
            ('A10 - Server Side Request Forgery')
            ]

@app.template_filter('owaspcategorie')
def owaspcategorie(num):
    if num:
        return owasptop10[int(num)-1]
    else:
        return 'A5 - Security Misconfiguration'

@app.template_filter('bevindingnums')
def bevindingnums(nums):

    reek =','.join(nums)
    return reek


def refnaam(t):

    for x in htmlrefs:
        if x[0] == t:
            return x[1]

    return 'Geen referentie gevonden!!!'

@findings_bp.route('/dashboard/findings/add/<bevinding_id>', methods=['GET', 'POST'])
def bevinding_toevoegen(bevinding_id):

    form = BevindingForm(ref=bevinding_id)
    pagina = render_template('bevinding_toevoegen.html', form=form)
    return pagina


@findings_bp.route('/dashboard/findings/edit/<bevinding_id>', methods=['GET', 'POST'])
def bevinding_bewerken(bevinding_id):

    item = db_bevindingen.query.filter_by(id=bevinding_id).first()

    form = BevindingForm(id=item.id, naam=item.naam, invoegen=item.invoegen, ref=item.ref, uitwerken=item.uitwerken, locatie=item.locatie, gebruikersvlag=item.gebruikersvlag, rootvlag=item.rootvlag)
    pagina = render_template('bevinding_toevoegen.html', form=form)
    return pagina

@findings_bp.route('/dashboard/findings/delete/<int:bevindingen_id>', methods=['GET'])
def bevinding_verwijderen(bevindingen_id):
        verwijder = db_bevindingen.query.filter_by(id=bevindingen_id).first()
        db.session.delete(verwijder)
        db.session.commit()
        return '<strong>DELETED!</strong>'


@findings_bp.route('/dashboard/findings/save', methods=['POST'])
def bevinding_opslaan():

    form = BevindingForm()
    if form.validate_on_submit():

        try:
            if int(form.id.data):
                bev = db_bevindingen.query.get(form.id.data)
                bev.naam = form.naam.data
                bev.invoegen = form.invoegen.data
                bev.ref = form.ref.data
                bev.uitwerken = form.uitwerken.data
                bev.locatie = form.locatie.data
                bev.basescore =  form.basescore.data
                bev.cvss =  form.cvss.data
                bev.gebruikersvlag =  form.gebruikersvlag.data
                bev.rootvlag = form.rootvlag.data
                db.session.commit()


        except:

            bevdb = db_bevindingen(naam=form.naam.data, invoegen=form.invoegen.data, ref=form.ref.data, uitwerken=form.uitwerken.data, locatie=form.locatie.data, gebruikersvlag=form.gebruikersvlag.data, rootvlag=form.rootvlag.data, basescore=form.basescore.data, cvss=form.cvss.data)
            db.session.add(bevdb)
            db.session.commit()


    return redirect(url_for('index_bp.index', cms_pag='verwerkt'))


@findings_bp.route('/dashboard/findings/rapport', methods=['GET'])
def gen_rapport():

    bevindingen = db_bevindingen.query.group_by(db_bevindingen.ref).all()
    #notities = db_notes.query.filter_by(rapport=True).order_by(db_notes.volgorde.desc()).all()

    #notities halen

    #owasptop tien

    rapport=''
    rapport=''

    management_nl = ''
    management_en = ''
    notes = ''
    owasp = []
    kritiek = []
    hoog = []
    midden = []
    laag = []
    nihil = []
    notes = ''




    for bevinding in bevindingen:
        template = db_bevindingen_templates.query.filter_by(id=bevinding.ref).first()
        items = db_bevindingen.query.filter_by(ref=bevinding.ref).all()


        bevnums = []
        aantal = 0
        for x in items:
            aantal = aantal + 1
            bevnums.append(str(x.id).zfill(3))
            htmlrefs.append(['bev'+str(x.id), str(x.id).zfill(3)+' '+x.naam])


        notes = notes + render_template('notes.html', bevinding=items, template=template)
        #notes = notes + render_template('notes_nl.html', bevinding=items, template=template)

        #dutch report
        rapport = rapport + render_template('findings_nl.html', bevinding=items, template=template, bevnums=bevnums, aantal=aantal)

    




    #afbeeldingen bakken




    #build owasp_template





    #kleurtjes










    #fix jina template for latex
    rapport = rapport.replace("'[{'",'{').replace("'}]'",'}')
    notes = notes.replace("'[{'",'{').replace("'}]'",'}')
    tex = '\section{Verkenning \& ontdekking}'+notes+'\\newpage \section{Bevindingen}\n'+rapport
    schrijven('rapport/findings_nl.tex',tex)


    #create HTML version of rapport to make it Markdown friendly.

    #convert latexz


    section = re.compile('\\\\section{(.*)}')
    uitwerking = re.compile('\\\\uitwerking{(.*)}')
    bevind = re.compile('\\\\bevinding{(.*)}')
    subsection = re.compile('\\\\subsection{(.*)}')
    subsubsection = re.compile('\\\\subsubsection{(.*)}')

    images = re.compile('\\\\plaatje{(.*)}{(.*)}')   
    res = re.compile('\\\\item(.*)\\n') 
    haakjes = re.compile('\\\\haakjes{(.*)} +', re.MULTILINE) 
    opdracht = re.compile('\\\\opdracht{(.*)}') 
    arceren = re.compile('§\\\\hl{(.*)}§')
    label = re.compile('\\\\label{(.*)}')
    footnote = re.compile('\\\\footnote{(.*)}')
    textbf = re.compile('\\\\textbf{(.*)}')

    bevindingkop = re.compile('\\\\bevindingkop{(.*)}{(.*)}{(.*)}')
    result = section.findall(tex)
    result2 = subsection.findall(tex)
    result3 = subsubsection.findall(tex)
    result5 = images.findall(tex)

    result6 = uitwerking.findall(tex)
    result7 = haakjes.findall(tex)
    result8 = opdracht.findall(tex)
    result9 = arceren.findall(tex)
    labels = label.findall(tex)
    textbfs = textbf.findall(tex)
    bevinds = bevind.findall(tex)
    bevindk = bevindingkop.findall(tex)
    footnotes = footnote.findall(tex)



    voetteller = 0
    voetten = ''


    for x in result3:

        tex = tex.replace('\\subsubsection{'+str(x)+'}','<h3>'+str(x)+'</h3>')

    for x in result2:
        tex = tex.replace('\\subsection{'+str(x)+'}','<h2>'+str(x)+'</h2>')


    for x in result:
        tex = tex.replace('\\section{'+str(x)+'}','<h1>'+str(x)+'</h1>')


    for x in result6:

        tex = tex.replace('\\uitwerking{'+str(x)+'}','<p>We werken dit uit verder uit in bevinding <a href="#'+str(x)+'"><em>&ldquo;'+str(refnaam(x))+'&rdquo;</em></a>.')

    for x in bevinds:

        tex = tex.replace('\\bevinding{'+str(x)+'}','<p><a href="#'+str(x)+'"><em>&ldquo;'+str(refnaam(x))+'&rdquo;</em></a>')


    for x in result7:

        tex = tex.replace('\haakjes{'+str(x)+'}','<em>&ldquo;'+str(x)+'&rdquo;</em>')


    for x in bevindk:

        tabel='<table><thead><tr><td><small>ID</small></td><td><small>Categorie</small></td><td><small>CWE</small></td></tr></thead><tr><td>'+str(x[0])+'</td><td>'+str(x[1])+'</td><td>'+str(x[2])+'</td></tr></table>'

        tex = tex.replace('\\bevindingkop{'+x[0]+'}{'+x[1]+'}{'+x[2]+'}', tabel)


    for x in textbfs:

        tex = tex.replace('\\textbf{'+str(x)+'}','<strong>'+str(x)+'</strong>')

    for x in labels:

        tex = tex.replace('\\label{'+str(x)+'}','<span id="'+str(x)+'"></span>')

    for x in footnotes:
        voetteller = voetteller+1

        tex = tex.replace('\\footnote{'+str(x)+'}','[^voetnoot'+str(voetteller)+']')
        voetten=voetten + '<p>[^voetnoot'+str(voetteller)+']: <small>'+str(x)+'</small></p>'

    for x in result8:

        tex = tex.replace('\\opdracht{'+str(x)+'}','<code>'+str(x)+'</code>')

    for x in result9:

        tex = tex.replace('§\hl{'+str(x)+'}§','<mark>'+str(x)+'</mark>')

    for x in result5:

        tex = tex.replace('\\plaatje{'+x[0]+'}{'+x[1]+'}','<img src="../raw/screenshots/'+str(x[0])+'" alt="'+str(x[1])+'" />')

    '''    
    for x in res:
        #tex = tex.replace('\\\\item'+str(x)+'\n','<li>'+str(x)+'</li>\n')
        print(x)
    '''


    tex = tex.replace('\\begin{description}', '<ul>').replace('\end{description}', '</ul>').replace('\item', '<li>')
    tex = tex.replace('\\begin{itemize}', '<ul>').replace('\\end{itemize}', '</ul>')
    tex = tex.replace('\\begin{lstlisting}', '<pre>').replace('\end{lstlisting}', '</pre>')

    tex = tex.replace('\\newpage', '<div style="page-break-after: always"></div>').replace("\&","&amp;")




    haakjes2 = re.compile('\\\\haakjes{(.*)}') 
    result7 = haakjes2.findall(tex)
    for x in result7:

        tex = tex.replace('\haakjes{'+str(x)+'}','<em>&ldquo;'+str(x)+'&rdquo;</em>')



    
    html = ''
    for x in tex.split('\n'):

        if x.lstrip().startswith('<li>'):
            x = x+'</li>\n'
        if x.lstrip().startswith('<li>['):
            x = x.replace('[', '<strong>').replace(']', '</strong>')
        html = html + x

    schrijven('rapport/tex.html', html+voetten)



    md = pandoc('rapport/tex.html', '-o', 'rapport/tex.md')


    #voetnotes fixxen
    md = lezen('rapport/tex.md')
    md = md.replace("\[\^","[^")
    md = md.replace("\]","]")
    #md = md.replace('::: {style="page-break-after: always"}', '<div style="page-break-after: always"></div>')
    #md = md.replace(':::','')

    toevoegen = '''---
title: "Pentest Rapport"
subtitle: "Rapportage"
author: Incompetent Bastard
date: today

...
<div style="page-break-after: always"></div>
'''

    schrijven('rapport/tex.md', toevoegen+'\n'+md)



    return '<html><style>pre {background:#ccc;} img{width:99%} table{width:100%}</style><body>'+html+'</html></body>'  