from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Required, Regexp
from FileTransferPackage.models import User

class AccountCreationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=25, message='You cannot have more than 25 characters')])
    surname = StringField('Surname', validators=[DataRequired(), Length(min=2, max=30, message='You cannot have more than 30 characters')])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    admin_checkbox = BooleanField('admin')
    moderator_checkbox = BooleanField('moderator')
    normal_checkbox = BooleanField('normal')
    submit = SubmitField('Create')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
           raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
           raise ValidationError('That email is taken. Please choose a different one.')
           
class AccountEditForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=25, message='You cannot have more than 25 characters')])
    surname = StringField('Surname', validators=[DataRequired(), Length(min=2, max=30, message='You cannot have more than 30 characters')])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    admin_checkbox = BooleanField('admin')
    moderator_checkbox = BooleanField('moderator')
    normal_checkbox = BooleanField('normal')
    submit = SubmitField('Update')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    captcha = StringField('Captcha', validators=[DataRequired(), Length(4, 4)])	
    submit = SubmitField('Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('No account with that email. Request admin to create you an account.')
    
class AccountResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[\
	                Regexp(".*[A-Z].*", message="Password must contain at least one capital letter."), \
					Regexp(".*[a-z].*", message="Password must contain at least one small letter."), \
					Regexp(".*[0-9].*", message="Password must contain at least one number."),\
					Regexp(".*[!@#$%&*?<>{}].*", message="Password must contain at least one of !@#$%&*?<>{} characters."), \
					Regexp("^.{8,15}$", message="Password must be between 8-15 characters.") \
					])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Submit')
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=35)])
    password = PasswordField('Password', validators=[DataRequired()])
    token = StringField('Token', validators=[Required(), Length(6, 6)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
    
class FileUploadForm(FlaskForm):
    file = FileField('Format: .rar, .zip, .tar', validators=[FileRequired(), FileAllowed(['rar', 'zip', 'tar'])])
    comment = TextAreaField('comment:', validators=[Length(min=10, max=500)])
    recipients = TextAreaField('recipients:', validators=[], render_kw={"placeholder": "Don't need to put yourself or a moderator as a recipient!"})
    submit = SubmitField('Send')
    
class ReqFWForm(FlaskForm):
    comment = TextAreaField('comment:', validators=[Length(min=10, max=500)])
    recipients = TextAreaField('recipients:', validators=[], render_kw={"placeholder": "Don't need to put yourself or a moderator as a recipient!"})
    req_id = HiddenField('Req_id')
    submit = SubmitField('Send')
    
class ReqEditForm(FlaskForm):
    comment = TextAreaField('comment:', validators=[Length(min=10, max=500)])
    recipients = TextAreaField('recipients:', validators=[])
    submit = SubmitField('Update')