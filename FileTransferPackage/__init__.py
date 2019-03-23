import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail

basedir = os.path.abspath(os.path.dirname(__file__))

appFlask = Flask(__name__)
appFlask.config["SECRET_KEY"] = "o\xde\x87&\xf9\xc7\x00hJ*\xe5\x94\xbd\xd3\xef\x8a\xa3D\xa3P\x8b\x1a:]"
appFlask.config['UPLOAD_FOLDER'] = "/home/vas/PythonProjects/Quarantine"
appFlask.config["DEBUG"] = False

appFlask.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "DB/FileTransfer.db")
appFlask.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(appFlask)
bcrypt = Bcrypt(appFlask)

login_manager = LoginManager(appFlask)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

appFlask.config['MAIL_SERVER'] = 'smtp.gmail.com'
appFlask.config['MAIL_PORT'] = 465   #587
appFlask.config['MAIL_USE_TLS'] = False
appFlask.config['MAIL_USE_SSL'] = True
appFlask.config['MAIL_USERNAME'] = "" #os.environ.get('EMAIL_USER')
appFlask.config['MAIL_PASSWORD'] = "" #os.environ.get('EMAIL_PASS')
mail = Mail(appFlask)

from FileTransferPackage import routes
