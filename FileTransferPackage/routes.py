from flask import render_template, url_for, flash, jsonify, redirect, request, send_from_directory, session
from FileTransferPackage import appFlask, db, bcrypt, mail
from FileTransferPackage.forms import (AccountCreationForm, AccountEditForm, LoginForm, FileUploadForm,
         RequestResetForm, AccountResetPasswordForm, ReqEditForm, ReqFWForm)
from FileTransferPackage.models import User, Request, State, UserRequest, Role
from flask_login import login_user, current_user, logout_user, login_required
import datetime
import hashlib
import os, re
import json
import shutil
from flask_mail import Message
from functools import wraps
import pyqrcode
from io import BytesIO
import base64

myreferrer="/"

def moderator_required(Orig_func):
   @wraps(Orig_func)
   def wrapper_func(*args, **kwargs):
     if current_user.permission != 6 and current_user.permission != 2: # admin+moderator and moderator
       flash("Not allowed, you must login as moderator!", 'danger')
       return redirect(url_for('panel'))
     else:
       return Orig_func(*args,**kwargs)
   return wrapper_func

def admin_required(Orig_func):
   @wraps(Orig_func)
   def wrapper_func(*args, **kwargs):   
     if current_user.permission != 6 and current_user.permission != 4: # admin+moderator and admin
       flash('Not allowed, you must login as an admin!', 'danger')
       return redirect(url_for('panel'))
     else:
       return Orig_func(*args,**kwargs)
   return wrapper_func 
   
@appFlask.route("/")
@appFlask.route("/home")
def home():
    if current_user.is_authenticated:
      return redirect(url_for('panel'))
    else:
      return render_template('home.html')
           
@appFlask.route("/panel")
@login_required
def panel():
    all_page = request.args.get('all_page', 1, type=int)
    in_page = request.args.get('in_page', 1, type=int)
    out_page = request.args.get('out_page', 1, type=int)
       
    if current_user.permission == 6 or current_user.permission == 2:   # admin+moderator  or  moderator
       all_reqs = Request.query.order_by(Request.req_date.desc()).paginate(page=all_page, per_page=3)
       in_reqs = current_user.in_reqs.order_by(Request.req_date.desc()).paginate(page=in_page, per_page=2)
       out_reqs = current_user.out_reqs.order_by(Request.req_date.desc()).paginate(page=out_page, per_page=1)
       return render_template('panel_moderator.html', all_reqs=all_reqs, in_reqs=in_reqs, out_reqs=out_reqs, all_page=all_page, in_page=in_page, out_page=out_page)
    elif current_user.permission == 4 or current_user.permission == 0:  # admin or normal
       out_reqs = current_user.out_reqs.order_by(Request.req_date.desc()).paginate(page=out_page, per_page=3)
       in_reqs = current_user.in_reqs.order_by(Request.req_date.desc()).paginate(page=in_page, per_page=3)
       return render_template('panel_normal.html', out_reqs=out_reqs, in_reqs=in_reqs)

@appFlask.route('/ajax/revComment')
@login_required
@moderator_required
def rev_comment():
    myreviewerCommentTxt= request.args.get('revComment', '', type=str)    
    myReqID = request.args.get('req_id', 0, type=int)
    myReq = Request.query.get(myReqID)
    myReq.reviewer_comment = myreviewerCommentTxt
    db.session.commit()    

@appFlask.route('/ajax/user_req_info')
@login_required
def user_req_info():
    myReqID = request.args.get('req_id', 0, type=int)
    myReq = Request.query.get(myReqID)

    if current_user == myReq.requester or (current_user in myReq.recipients) or current_user.permission == 6 or current_user.permission == 2:
      info_desc = myReq.description
      info_recip = ''.join(str(e) for e in myReq.recipients)
      info_req_date = myReq.req_date
      info_review_date = myReq.review_date
      info_reviewer_comment = myReq.reviewer_comment
      return jsonify({"desc":info_desc, "recip":info_recip, "req_date":info_req_date, "review_date":info_review_date, "rev_comment":info_reviewer_comment})
    else:
      flash("To see requests details, you must login as moderator!", 'danger')
      return redirect(url_for('panel'))    
    
@appFlask.route("/x_reqs")
@login_required
def x_reqs():  # user_reqs, state_reqs, all_reqs, in_reqs, out_reqs

    page = request.args.get('page', 1, type=int)
    state= request.args.get('state', '', type=str)
    username= request.args.get('username', current_user.username, type=str)
    type= request.args.get('type', '', type=str)
    
    if type=="all" or current_user.username != username:   # all or other user requests
      if current_user.permission != 6 and current_user.permission != 2:  # Moderator permission is needed
        flash("To see requests details, you must login as moderator!", 'danger')
        return redirect(url_for('panel'))
      elif type == 'all': 
         reqs = Request.query.order_by(Request.req_date.desc()).paginate(page=page, per_page=10)
      elif state != '':
         myuser=User.query.filter_by(username=username).first()
         mystate=State.query.filter_by(state=state).first()
         reqs = myuser.out_reqs.filter_by(state=mystate).order_by(Request.req_date.desc()).paginate(page=page, per_page=10)
      else:
         myuser=User.query.filter_by(username=username).first()
         reqs = myuser.out_reqs.order_by(Request.req_date.desc()).paginate(page=page, per_page=10)
      return render_template('x_reqs.html', reqs=reqs, type=type, username=username, state=state)    
         
    else:   # current_user requests
      if state!='':
         mystate=State.query.filter_by(state=state).first()
         reqs = current_user.out_reqs.filter_by(state=mystate).order_by(Request.req_date.desc()).paginate(page=page, per_page=10)
      elif type=='out':
         reqs = current_user.out_reqs.order_by(Request.req_date.desc()).paginate(page=page, per_page=10)
      elif type=='in':
         reqs = current_user.in_reqs.order_by(Request.req_date.desc()).paginate(page=page, per_page=10)
      return render_template('x_reqs.html', reqs=reqs, type=type, username=current_user.username, state=state)      


def md5(fname):
    hash_md5 = hashlib.md5()
    hash_md5.update(fname.encode("utf8"))
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    myDigest = hash_md5.hexdigest()
    return myDigest
    
def save_file(form_file):
    CHECK_DIGEST = False
    file_path = os.path.join(appFlask.config['UPLOAD_FOLDER'], 'tmp', form_file.filename)
    form_file.save(file_path)
    file_size=os.stat(file_path).st_size    
    file_digest=md5(file_path)
    if CHECK_DIGEST == True and Request.query.filter_by(FileDigest=file_digest).first():
        os.remove(file_path)
        return None, None, None
    else:
        f_name, f_ext = os.path.splitext(form_file.filename)
        timestamp = datetime.datetime.now().strftime("%y%m%d%H%M")
        unique_fname = f_name + "_" + timestamp + f_ext
        Dest_file_path = os.path.join(appFlask.config['UPLOAD_FOLDER'], unique_fname)
        shutil.move(file_path, Dest_file_path)
        return file_digest, unique_fname, file_size
    
@appFlask.route("/trans_req", methods=['GET', 'POST'])
@login_required    
def trans_req():
    if current_user.state == "blocked":
      flash('You have been blocked! Contact admin.', 'danger')
      return redirect(url_for('panel'))
    form = FileUploadForm()

    if form.validate_on_submit():        
        if form.file.data:
            file_digest, unique_fname, file_size = save_file(form.file.data)
            if not file_digest:
                flash('There is already a record of your file in DB', 'danger')
                return render_template('trans_req.html', form=form)    
            myRequest= Request(FileName=unique_fname, description=form.comment.data, requester=current_user, FileDigest=file_digest, FileSize=file_size)
            
            recipient_emails = re.findall(r'[\w\.-]+@[\w\.-]+', form.recipients.data)
            for email in recipient_emails:
               if email != current_user.email:
                  tmpUser=User.query.filter_by(email=email).first()
                  myRequest.recipients.append(tmpUser)
                               
            myRequest.state = State.query.filter_by(state='pending').first()
            db.session.commit() 
            
            flash('Your request is registered!', 'success')
        return redirect(url_for('panel'))
        
    users = User.query.order_by(User.surname)
    return render_template('trans_req.html', title='File Transfer Request', form=form, users=users)

@appFlask.route("/fw_req", methods=['GET', 'POST'])
@login_required    
def fw_req():
    global myreferrer
    if current_user.state == "blocked":
      flash('You have been blocked! Contact admin.', 'danger')
      return redirect(url_for('panel'))
      
    req_id=request.args.get('req_id', 0, type=int)

    form = ReqFWForm(req_id=req_id)

    if form.validate_on_submit():
        myreq_id = form.req_id.data    
        myReq=Request.query.get(myreq_id)
        if current_user == myReq.requester or (current_user in myReq.recipients) or current_user.permission == 6 or current_user.permission == 2:
          myRequest= Request(FileName=myReq.FileName, description=form.comment.data, requester=current_user, FileDigest=myReq.FileDigest, FileSize=myReq.FileSize)
          recipient_emails = re.findall(r'[\w\.-]+@[\w\.-]+', form.recipients.data)
          for email in recipient_emails:
             if email != current_user.email:
                tmpUser=User.query.filter_by(email=email).first()
                myRequest.recipients.append(tmpUser)
                               
          myRequest.state = State.query.filter_by(state='pending').first()
          db.session.commit() 
          
          flash('Your FW request is registered!', 'success')
        else:
          flash('Since you are not recipient of this request, you can not forward it', 'warning')
        return redirect(myreferrer, code="302")
    
    myreferrer = request.headers.get("Referer")
    users = User.query.order_by(User.surname)
    return render_template('fw_req.html', title='Forward Transfer Request', form=form, users=users)

@appFlask.route("/create_account", methods=['GET', 'POST'])
@login_required
@admin_required
def create_account():
    form = AccountCreationForm()
    if form.validate_on_submit():
        permission = form.admin_checkbox.data * 4 + form.moderator_checkbox.data * 2
        user = User(name=form.name.data, surname=form.surname.data, username=form.username.data, email=form.email.data, permission=permission, password="", otp_secret="")
 
        admin_role = Role.query.filter_by(role="admin").first()
        moderator_role = Role.query.filter_by(role="moderator").first()
        normal_role = Role.query.filter_by(role="normal").first()
        if permission == 6:
           user.roles.append(admin_role)
           user.roles.append(moderator_role)
        elif permission == 4:
           user.roles.append(admin_role)
        elif permission == 2:
           user.roles.append(moderator_role)
        else:
           user.roles.append(normal_role)
        
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
        send_reset_email(user)
        flash('The account has been created and email for password reset sent', 'success')
        return redirect(url_for('panel'))
    return render_template('create_account.html', title='Create Account', form=form)

@appFlask.route("/req_actions/<string:action>", methods=['GET', 'POST'])
@login_required
def req_actions(action):
    req_id = request.args.get('req_id', 0, type=int)
    myReq = Request.query.get_or_404(req_id)
    
    if current_user != myReq.requester and current_user.permission != 6 and current_user.permission != 2:
         flash('You must either be owner of this request or login as moderator!', 'danger')
         return redirect(url_for('panel'))
         
    if myReq.state.state != "pending":
        flash('The state of request is already decided!', 'danger')
        return redirect(url_for('panel'))
            
    if action == "approved" or action == "denied":
       if current_user.permission != 6 and current_user.permission != 2:
          flash('To approve or deny a request, you must login as moderator!', 'danger')
          return redirect(url_for('panel'))
 
    referrer = request.headers.get("Referer")
    if action=="approved" or action=="denied" or action == "cancelled":      
        myReq.state = State.query.filter_by(state=action).first()
        myReq.reviewer = current_user
        myReq.review_date = datetime.datetime.utcnow()
        db.session.commit()
        flash('Request state changed!', 'success')
    else:
        flash('Unsupported action!', 'danger')
    return redirect(referrer, code="302")

@appFlask.route("/edit_req/<int:req_id>", methods=['GET','POST'])
@login_required
def edit_req(req_id):
    myReq = Request.query.get_or_404(req_id)

    if current_user != myReq.requester and current_user.permission != 6 and current_user.permission != 2:        
         flash('You must either be owner of this request or login as moderator!', 'danger')
         return redirect(url_for('panel'))
         
    if myReq.state.state != "pending":
        flash('Request state is fixed. No more edite is possible', 'danger')
        return redirect(url_for('panel'))

    form = ReqEditForm()
         
    if form.validate_on_submit():
        myReq.description=form.comment.data
        
        myReq.recipients.clear()    
        db.session.commit()        
            
        recipient_emails = re.findall(r'[\w\.-]+@[\w\.-]+', form.recipients.data)
        for email in recipient_emails:
           if email != myReq.requester.email:
              tmpUser=User.query.filter_by(email=email).first()
              myReq.recipients.append(tmpUser)
                               
        myReq.recipients.append(myReq.requester) #Requester is always a default recipient of its own request file  
        db.session.commit()

        flash('The Request has been edited!', 'success')
        return redirect(url_for('panel'))
        
    if request.method == 'GET':
        form.comment.data = myReq.description
        form.recipients.data = ''.join(str(e) for e in myReq.recipients)
        users = User.query.order_by(User.surname)
        
    return render_template('edit_req.html', title='Edit Request', form=form, users=users)
    

@appFlask.route("/delete_account/<int:account_id>", methods=['GET','POST'])
@login_required
@admin_required
def delete_account(account_id):
    user = User.query.get_or_404(account_id)

    if user.permission == 6 and current_user.permission != 6: 
        flash('You need to be admin+moderator to touch this account!', 'danger')
        return redirect(url_for('panel'))    
        
    db.session.delete(user)
    db.session.commit()
    flash('The account has been deleted!', 'success')
    return redirect(url_for('delete_accounts'))

    
@appFlask.route("/delete_accounts", methods=['GET'])
@login_required
@admin_required
def delete_accounts():
    role = request.args.get('role', '', type=str)
    page = request.args.get('page', 1, type=int)
    if role == '':
       users = User.query.order_by(User.create_date.desc()).paginate(per_page=10, page=page)
    elif role == "admin" or role == "normal" or role == "moderator":
       myRole = Role.query.filter_by(role=role).first()
       users = myRole.users.order_by(User.surname).paginate(per_page=10, page=page)      
    else:
       flash('Given role is not supported', 'danger')
       return redirect(url_for('panel'))    
    return render_template('delete_accounts.html', title='Delete Account', users=users)


@appFlask.route("/edit_account", methods=['GET','POST'])
@login_required
def edit_account():
    if current_user.permission != 6 and current_user.permission != 4:
        flash('To edit a user profile, you must login as an admin!', 'danger')
        return redirect(url_for('panel'))
    form = AccountEditForm()
    
    account_id = request.args.get('account_id', 0, type=int)
    action = request.args.get('action', '', type=str)
    user = User.query.get_or_404(account_id)
    
    if user.permission == 6 and current_user.permission != 6: 
        flash('You need to be admin+moderator to touch this account!', 'danger')
        return redirect(url_for('panel'))    
    
    if form.validate_on_submit():
        myUsername=form.username.data
        myEmail=form.email.data
        userTest = User.query.filter_by(username=myUsername).first()
        if userTest:
            if userTest.id != account_id:
               flash('This username: '+ myUsername +' is already used', 'danger')
               return redirect(url_for('edit_user', account_id=account_id))
               
        emailTest = User.query.filter_by(email=myEmail).first()
        if emailTest:
            if emailTest.id != account_id:
               flash('This email: '+ myEmail +' is already used', 'danger')
               return redirect(url_for('edit_user', account_id=account_id))

        user.roles.clear()    
        db.session.commit()    
        
        user.username = myUsername
        user.email = myEmail
        permission = form.admin_checkbox.data * 4 + form.moderator_checkbox.data * 2

        admin_role = Role.query.filter_by(role="admin").first()
        moderator_role = Role.query.filter_by(role="moderator").first()
        normal_role = Role.query.filter_by(role="normal").first()
        if permission == 6:
           user.roles.append(admin_role)
           user.roles.append(moderator_role)
        elif permission == 4:
           user.roles.append(admin_role)
        elif permission == 2:
           user.roles.append(moderator_role)
        else:
           user.roles.append(normal_role)
           
        user.permission=permission
        user.name=form.name.data
        user.surname=form.surname.data
        db.session.commit()
        flash('The account has been updated!', 'success')
        return redirect(url_for('edit_accounts'))
    if request.method == 'GET':
      if action == '':
        form.name.data = user.name
        form.surname.data = user.surname    
        form.username.data = user.username
        form.email.data = user.email
        if user.permission == 6:
           form.admin_checkbox.data = True
           form.moderator_checkbox.data = True
        elif user.permission == 4:
           form.admin_checkbox.data = True
        elif user.permission == 2:
           form.moderator_checkbox.data = True
        else:
           form.normal_checkbox.data = True
        return render_template('edit_account.html', title='Edit User', form=form)
      elif action == 'blocked' or action == 'allowed':
        user.state = action
        db.session.commit()        
        return redirect(url_for('edit_accounts'))

@appFlask.route("/edit_accounts", methods=['GET'])
@login_required
@admin_required
def edit_accounts():
    role = request.args.get('role', '', type=str)
    page = request.args.get('page', 1, type=int)
    if role == '':
       users = User.query.order_by(User.create_date.desc()).paginate(per_page=10, page=page)
    elif role == "admin" or role == "normal" or role == "moderator":
       myRole = Role.query.filter_by(role=role).first()
       users = myRole.users.order_by(User.surname).paginate(per_page=10, page=page)      
    else:
       flash('Given role is not supported', 'danger')
       return redirect(url_for('panel'))    
    return render_template('edit_accounts.html', title='Edit Account', users=users)
    
@appFlask.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
         return redirect(url_for('panel'))
    form = LoginForm()
    if form.validate_on_submit():
        myUser = User.query.filter_by(username=form.username.data).first()
        if not myUser:  #Maybe entered email as username
           myUser = User.query.filter_by(email=form.username.data).first()

        if myUser and bcrypt.check_password_hash(myUser.password, form.password.data) and myUser.verify_totp(form.token.data):
           login_user(myUser, remember=form.remember.data)
           previous_login = str(myUser.last_login)
           myUser.last_login = datetime.datetime.utcnow()
           db.session.commit()           
           next_page = request.args.get('next')
           flash('Your previous login was at ' + previous_login, 'success')
           return redirect(next_page) if next_page else redirect(url_for('panel'))
        else:
           flash('Login Unsuccessful. Invalid username, password or token.', 'danger')
       
    return render_template('login.html', title='Login', form=form)
    
@appFlask.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
    
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='v.saljooghi87@gmail.com', recipients=[user.email])
    msg.body = "To reset your password, visit the following link:\n" + url_for('reset_token', token=token, _external=True) + "\nIf you did not make this request then simply ignore this email and no changes will be made."
    mail.send(msg)

@appFlask.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@appFlask.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = AccountResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        user.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        db.session.commit()
        flash('Your password has been updated! Next Step is to setup OTP', 'success')
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('reset_token.html', title='Reset Password', user=user, form=form)

@appFlask.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        flash('username not in session', 'warning')			
        return redirect(url_for('home'))

    user = User.query.filter_by(username=session['username']).first()
	
    if user is None:
        return redirect(url_for('home'))
		
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html', title='2F setup'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}
		
@appFlask.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    totp_spec = user.get_totp_uri()
    url = pyqrcode.create(totp_spec)
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}
		
@appFlask.route('/downloads', methods=['GET'])
@login_required
def download_file():
    FN = request.args.get('filename', type=str)
    myReq = Request.query.filter_by(FileName=FN).first()

    if current_user.permission == 6 or current_user.permission == 2:
        return send_from_directory(appFlask.config['UPLOAD_FOLDER'], FN, as_attachment=True)
    elif (current_user in myReq.recipients) or current_user == myReq.requester:
      if myReq.state.state == "approved":
        return send_from_directory(appFlask.config['UPLOAD_FOLDER'], FN, as_attachment=True)
      else:
        flash('To download the file, you need moderator approval first', 'warning')
        return redirect(url_for('panel'))
    else:
      flash('You are not a recipient or requester of this file', 'warning')    
      return redirect(url_for('panel'))
