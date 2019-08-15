<p> File transfer web application facilitates file transfer from one computer network to a second computer network. The user can upload a compressed file from his/her own panel on source network and then download the same file in a destination network or he/she can put   
other recipients as downloader of the file in the destination network.
This web app is handy in air-gapped environments with limited access(no Internet, closed USB ports and etc) for transferring file to 
an open access computer network (The web app acts as a gatekeeper between two networks).
It provides the capability for account management(create, edit, delete, block account) and request management(approve, cancel, deny, 
edit, forward). The file transfer request shall be reviewed by a reviewer and in case of approvement, the requester can download the file.</p>

![Screen Shot](https://raw.githubusercontent.com/vsaljooghi/File-Transfer-Web-App/master/FileTransferPackage/DOC/Diagram_FileTransfer.png)

![Screen Shot](https://raw.githubusercontent.com/vsaljooghi/File-Transfer-Web-App/master/FileTransferPackage/DOC/home_page.png)

![Screen Shot](https://raw.githubusercontent.com/vsaljooghi/File-Transfer-Web-App/master/FileTransferPackage/DOC/panel_moderator.png)

![Screen Shot](https://raw.githubusercontent.com/vsaljooghi/File-Transfer-Web-App/master/FileTransferPackage/DOC/DB_diagram.png)

![Screen Shot](https://raw.githubusercontent.com/vsaljooghi/File-Transfer-Web-App/master/FileTransferPackage/DOC/edit_accounts.png)

![Screen Shot](https://raw.githubusercontent.com/vsaljooghi/File-Transfer-Web-App/master/FileTransferPackage/DOC/delete_accounts.png)

![Screen Shot](https://raw.githubusercontent.com/vsaljooghi/File-Transfer-Web-App/master/FileTransferPackage/DOC/trans_req.png)

![Screen Shot](https://raw.githubusercontent.com/vsaljooghi/File-Transfer-Web-App/master/FileTransferPackage/DOC/QR_2FA.png)


##### Security:
------------------
##### 0- Prevention of Cross-Site Request Forgery(CSRF/XSRF) attack.
##### 1- Prevention of Cross-Site Scripting(XSS) attack.
##### 2- Using Captcha to prevent denial of service(DOS) attack.
##### 3- Using complex password policy.
##### 4- Using one-time password(OTP) to implement two-factor authentication. (To set up it on Android smart phones: you can use FreeOTP apk)
##### 5- Set up of HTTP header to avoid caching of sensitive data (In case a third person uses browser back button to retrieve panel after logout)

### How to setup:

##### In __init__.py
--------------------
##### 0- setup configuration for mail server credential.

##### 1- setup path to upload folder: appFlask.config['UPLOAD_FOLDER'] = "Path/to/Quarantine/Folder"



##### To initiate first user in an empty database:
-------------------------------------
##### 0- Change to root of application folder and then run python REPL and then run the following commands: 

##### 1- from FileTransferPackage import db,bcrypt

##### 2- from FileTransferPackage.models import *

##### 3- db.create_all()

##### 4- pass1=bcrypt.generate_password_hash("123456").decode('utf-8')

##### 5- u1=User(name="admin", surname="adminian", username="adm", email="admin@example.com", password=pass1, permission=6)

##### 6- db.session.add(u1)

##### 7- db.session.commit()


### User Privileges:

##### Permission:
------------
| admin + moderator | admin |   moderator   |  normal  |
|:-----------------:|:-----:|:-------------:|:--------:|
|         6         |   4   |       2       |     0    |


##### Admin(4):
-----------
##### 0- Can "cancel or edit"(review) his/her own requests.
##### 1- Can request file transfer to be reviewed later by a moderator.
##### 2- Can create non moderator(admin or normal) account and delete, block or edit any account except most privileged one(admin + moderator). 
##### 3- Can not create an account with moderator privilege.
##### 4- Can view and download other's approved requests of which he/she is a recipient.

##### Moderator(2):
---------------
##### 0- Can "cancel, edit, approve or deny"(review) his/her own requests.
##### 1- Can "approve, deny or edit"(review) other's requests.
##### 2- Can not create, delete or edit account

##### Normal(0):
------------
##### 0- Can "cancel or edit"(review) his/her own requests.
##### 1- Can request file transfer to be reviewed later by a moderator.
##### 2- Can not "create, delete or edit" account.
##### 3- Can not "approve, deny or edit"(review) other's requests.
##### 4- Can view and download other's approved requests of which he/she is a recipient.

##### Admin + Moderator(6):
----------------------- 
##### *Can do everything
 
 
### Some Helpful commands for maintainer:
----------------------------------------
##### User.__table__.drop(db.engine)
##### User.__table__.create(db.engine)

##### UserRequest.drop(db.engine)
##### UserRequest.create(db.engine)

##### User.query.all()
##### User.query.first()
##### User.query.get(id)
##### db.drop_all()
##### db.session.rollback()

##### sqlite3:
----------
##### .tables
##### .schema 
##### .quit
##### .help
##### .open mydb.db
##### .mode column
##### .header on/off

FileTransferWebApp/
├── FileTransferPackage
│   ├── DB
│   │   └── FileTransfer.db
│   ├── forms.py
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── static
│   │   ├── css
│   │   │   ├── all.min.css
│   │   │   ├── bootstrap-grid.min.css
│   │   │   ├── bootstrap-grid.min.css.map
│   │   │   ├── bootstrap.min.css
│   │   │   ├── bootstrap.min.css.map
│   │   │   ├── bootstrap-reboot.min.css
│   │   │   ├── bootstrap-reboot.min.css.map
│   │   │   └── main.css
│   │   ├── img
│   │   │   ├── FileTransfer.png
│   │   │   └── searchicon.png
│   │   ├── js
│   │   │   ├── AJAX2GetReqInfo.js
│   │   │   ├── bootstrap.bundle.js
│   │   │   ├── bootstrap.bundle.js.map
│   │   │   ├── bootstrap.bundle.min.js
│   │   │   ├── bootstrap.bundle.min.js.map
│   │   │   ├── bootstrap.js
│   │   │   ├── bootstrap.js.map
│   │   │   ├── bootstrap.min.js
│   │   │   ├── bootstrap.min.js.map
│   │   │   ├── delUser.js
│   │   │   ├── ImportContacts.js
│   │   │   ├── jquery-3.3.1.js
│   │   │   ├── reqAction.js
│   │   │   ├── searchContacts.js
│   │   │   └── SelectContacts.js
│   │   └── webfonts
│   │       ├── fa-brands-400.eot
│   │       ├── fa-brands-400.svg
│   │       ├── fa-brands-400.ttf
│   │       ├── fa-brands-400.woff
│   │       ├── fa-brands-400.woff2
│   │       ├── fa-regular-400.eot
│   │       ├── fa-regular-400.svg
│   │       ├── fa-regular-400.ttf
│   │       ├── fa-regular-400.woff
│   │       ├── fa-regular-400.woff2
│   │       ├── fa-solid-900.eot
│   │       ├── fa-solid-900.svg
│   │       ├── fa-solid-900.ttf
│   │       ├── fa-solid-900.woff
│   │       └── fa-solid-900.woff2
│   └── templates
│       ├── create_account.html
│       ├── delete_accounts.html
│       ├── edit_account.html
│       ├── edit_accounts.html
│       ├── edit_req.html
│       ├── fw_req.html
│       ├── home.html
│       ├── includes
│       │   ├── _colorize.html
│       │   └── _formhelpers.html
│       ├── layout.html
│       ├── login.html
│       ├── panel_moderator.html
│       ├── panel_normal.html
│       ├── reset_request.html
│       ├── reset_token.html
│       ├── trans_req.html
│       └── x_reqs.html
├── README.md
└── run.py

