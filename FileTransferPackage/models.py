from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from FileTransferPackage import db, login_manager, appFlask
from flask_login import UserMixin
import os
import base64
import onetimepass

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

UserRequest = db.Table('UserRequest',   #Junction Table
   db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
   db.Column('req_id', db.Integer, db.ForeignKey('request.id'), primary_key=True),
)

UserRole = db.Table('UserRole',    #Junction Table
   db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
   db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
)

class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10), unique=True, nullable=False)

class Request(db.Model):
    __tablename__ = 'request'
    id = db.Column(db.Integer, primary_key=True)
    FileName = db.Column(db.String(100), nullable=False)
    req_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    review_date = db.Column(db.DateTime)    
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.Text, nullable=False)
    reviewer_comment = db.Column(db.Text)
    state_id = db.Column(db.Integer, db.ForeignKey('state.id'))
    FileDigest = db.Column(db.String(32), nullable=False)  #MD5 32 hexadecimal characters 
    FileSize = db.Column(db.Integer, nullable=False)    

    def __repr__(self):
        return "Request("+self.FileName+", "+self.req_date.strftime("%y%m%d%H%M")+", "+self.description+")"
    
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    otp_secret = db.Column(db.String(16), nullable=False)
    surname = db.Column(db.String(25), nullable=False)
    name = db.Column(db.String(15), nullable=False)
    permission = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(35), unique=True, nullable=False)
    password = db.Column(db.String(15), nullable=False)
    create_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    in_reqs = db.relationship("Request", secondary=UserRequest, lazy='dynamic', backref=db.backref('recipients', lazy=True))
    roles = db.relationship("Role", secondary=UserRole,  lazy=True, backref=db.backref('users', lazy='dynamic'))
    reviewed_reqs = db.relationship('Request', backref='reviewer', lazy='dynamic', foreign_keys=Request.reviewer_id)
    out_reqs = db.relationship('Request', backref='requester', lazy='dynamic', foreign_keys=Request.requester_id)
    last_login = db.Column(db.DateTime, nullable=False, default=datetime(1970,1,1))
    state = db.Column(db.String(15), nullable=False, default="allowed")
	
    '''
      def __init__(self, **kwargs):
      super(User, self).__init__(**kwargs)
      if self.otp_secret is None:
      # generate a random secret
      self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    '''

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-FileTransWebApp:{0}?secret={1}&issuer=2FA-FileTransWebApp&algorithm=SHA1&digits=6&period=300'.format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret, interval_length=300)
		
    def get_reset_token(self, expires_sec=1800):       	
        s = Serializer(appFlask.config["SECRET_KEY"] , expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(appFlask.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return self.name + "," + self.surname + "<" + self.email + ">; "

class State(db.Model):
    __tablename__ = 'state'
    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.String(15), nullable=False)  # cancelled(gray), approved(green), denied(red), pending(yellow) 
    reqs = db.relationship('Request', backref='state', lazy='dynamic')
