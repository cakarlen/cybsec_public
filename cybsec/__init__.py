from functools import wraps
from flask import Flask
from flask_login import LoginManager, current_user
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

app = Flask(__name__, template_folder='../templates', static_folder="../static")
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["MAIL_SERVER"] = "uky-edu.mail.protection.outlook.com"
app.config["MAIL_PORT"] = 25
app.config["MAIL_DEFAULT_SENDER"] = "cybersecurity@uky.edu"
app.config["MAIL_USERNAME"] = "cybersecurity@uky.edu"
app.config["MAIL_USE_TLS"] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "You are not authorized to access this page!"


@app.before_first_request
def create_tables():
    from cybsec.models import User, DmcaHistory, GeorgeQuotes, FoodList, Twss, edl_IPList, \
        edl_URLList, linkLists, Pastebin, api_table
    db.create_all()


def login_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            #split the roles
            split_current_role = current_user.role.split()
            split_required_roles = role.split()
            is_auth = False  # bool flag

            # check if the user role is valid
            for curr_role in split_current_role:
                if curr_role in split_required_roles:
                    is_auth = True

            if not is_auth:
                return login_manager.unauthorized()

            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


import cybsec.routes
