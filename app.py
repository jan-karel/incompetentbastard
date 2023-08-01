"""Initialize app."""
import os
from flask import Flask, render_template
from flask_bootstrap import Bootstrap
#from flask_caching import Cache
#from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
#from flask_wtf.csrf import CSRFProtect


#from .functies import return_csp_view


db = SQLAlchemy()
#login_manager = LoginManager()



def create_app():
    """Construct the core app object."""
    app = Flask(__name__, instance_relative_config=False)


    app.config['SECRET_KEY'] = 'Kl1M44t2CH44mT3'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///{0}/meuk/flask/db/db.sqlite'.format(os.path.dirname(__file__)))
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    # Application Configuration
    #app.config.from_object('config.Config')

    # Initialize Plugins
    db.init_app(app)
    #login_manager.init_app(app)
    #csrf = CSRFProtect(app)
    bootstrap = Bootstrap(app)
    migrate = Migrate(app, db)
    #cache = Cache(app)





    with app.app_context():

        db.create_all()
        from meuk.flask import index
        from meuk.flask import xxe
        from meuk.flask import download
        from meuk.flask import upload
        from meuk.flask import xxs
        #from meuk.flask import rfi
        #from meuk.flask import sqli2
        #from meuk.flask import c2
        # Register Blueprints
        app.register_blueprint(index.index_bp)
        app.register_blueprint(xxe.xxe_bp)
        app.register_blueprint(download.download_bp)
        app.register_blueprint(upload.upload_bp)
        app.register_blueprint(xxs.xxs_bp)
        #app.register_blueprint(rfi.rfi_bp)
        #app.register_blueprint(sqli2.sqli2_bp)





        return app



if __name__ == "__main__":
    create_app()