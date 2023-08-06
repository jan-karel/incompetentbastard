from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
from meuk.flask.models import *
from meuk.flask.forms import *
import glob



appdata = db_instellingen.query.first()

# Blueprint Configuration
findings_bp = Blueprint('findings_bp', __name__,
                    template_folder='html',
                    static_folder='static')


#basic website

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
                bev.gebruikersvlag =  form.gebruikersvlag.data
                bev.rootvlag = form.rootvlag.data
                db.session.commit()


        except:

            bevdb = db_bevindingen(naam=form.naam.data, invoegen=form.invoegen.data, ref=form.ref.data, uitwerken=form.uitwerken.data, locatie=form.locatie.data, gebruikersvlag=form.gebruikersvlag.data, rootvlag=form.rootvlag.data)
            db.session.add(bevdb)
            db.session.commit()


    return redirect(url_for('index_bp.index', cms_pag='verwerkt'))   