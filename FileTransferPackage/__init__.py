import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_session import Session
from flask_session_captcha import FlaskSessionCaptcha

basedir = os.path.abspath(os.path.dirname(__file__))

appFlask = Flask(__name__)
appFlask.config["SECRET_KEY"] = "o\xde\x87&\xf9\xc7\x00hJ*\xe5\x94\xbd\xd3\xef\x8a\xa3D\xa3P\x8b\x1a:]"

appFlask.config['REMEMBER_COOKIE_HTTPONLY'] = True # To protect against(prevent) Cross-Site Scripting(XSS) attack by avoiding malicious Javascript code to read/see this cookie 
appFlask.config['SESSION_COOKIE_HTTPONLY'] = True  # To protect against(prevent) Cross-Site Scripting(XSS) attack by avoiding malicious Javascript code to read/see this cookie 
appFlask.jinja_env.autoescape = True # Prevent Cross-Site Scripting(XSS) by Jinja2 auto escaping all values loaded in the page

appFlask.config['UPLOAD_FOLDER'] = "/home/vas/PythonProjects/Quarantine"
appFlask.config["DEBUG"] = False

appFlask.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "DB/FileTransfer.db")
appFlask.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(appFlask)
bcrypt = Bcrypt(appFlask)

login_manager = LoginManager(appFlask)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"   # A computer that is compromised can be used to access sensitive cookies. In this mode, Flask-Login will mark a user as logged out when it detects that an existing session suddenly appears to come from a different originating IP address or a different browser. 

appFlask.config['CAPTCHA_ENABLE'] = True
appFlask.config['CAPTCHA_NUMERIC_DIGITS'] = 5
appFlask.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'
appFlask.config['SESSION_TYPE'] = 'sqlalchemy'
Session(appFlask)
captcha = FlaskSessionCaptcha(appFlask)

appFlask.config['MAIL_SERVER'] = 'smtp.gmail.com'
appFlask.config['MAIL_PORT'] = 465   #587
appFlask.config['MAIL_USE_TLS'] = False
appFlask.config['MAIL_USE_SSL'] = True
appFlask.config['MAIL_USERNAME'] = "" #os.environ.get('EMAIL_USER')
appFlask.config['MAIL_PASSWORD'] = "" #os.environ.get('EMAIL_PASS')
mail = Mail(appFlask)

from FileTransferPackage import routes
