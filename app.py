from flask import Flask, url_for, render_template, request, redirect, session, flash, redirect, g, Response
from flask_sqlalchemy import SQLAlchemy
#from flask import current_app
#------for password hashing----
#from werkzeug.security import generate_password_hash, check_password_hash
#-------
from flask_login import LoginManager,UserMixin,login_user,login_required,logout_user,current_user
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_mail import *
import secrets
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import math
import uuid
import sqlite3
#from flask.ext.mail import Mail,Message
#----
from flask import Flask,send_from_directory,render_template
from flask import send_from_directory
from flask_restful import Resource, Api
from package.land import Lands, Land
from package.seller import Sellers, Seller
from package.appointment import Appointments, Appointment
from package.common import Common
from package.caveat import Caveat, Caveats
from package.landtitle import Landtitle, Landtitles
from package.location import Location, Locations
from package.buyer import Buyer, Buyers
from package.procedure import Procedure, Procedures
from package.agreement import Agreement, Agreements
from package.buy_sell_transaction import Buy_sell_transactions, Buy_sell_transaction

from templates.user_login.package.land import Lands, Land
from templates.user_login.package.seller import Sellers, Seller
from templates.user_login.package.appointment import Appointments, Appointment
from templates.user_login.package.common import Common
from templates.user_login.package.caveat import Caveat, Caveats
from templates.user_login.package.landtitle import Landtitle, Landtitles
from templates.user_login.package.location import Location, Locations
from templates.user_login.package.buyer import Buyer, Buyers
from templates.user_login.package.procedure import Procedure, Procedures
from templates.user_login.package.agreement import Agreement, Agreements
from templates.user_login.package.buy_sell_transaction import Buy_sell_transactions, Buy_sell_transaction

import json
import os
# transfered from user
from flask import Flask, flash, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
#from flask.ext.session import Session
from flask_sessions import Session
#


#import pyautogui
#import time
#------

#PEOPLE_FOLDER = os.path.join('static', 'images')
with open('config.json') as data_file:
    config = json.load(data_file)

app = Flask(__name__, static_url_path='')

#app.config['UPLOAD_FOLDER'] = PEOPLE_FOLDER

bcrypt = Bcrypt(app)

api = Api(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
#app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///employer.sqlite3'
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hosp.db'
app.config['SECRET_KEY'] = '0527'
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
#app.config['TESTING'] = False

#Transfered from user
app.config["SECRET_KEY"]="65b0774279de460"
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
#app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///ums.sqlite"
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"]='filesystem'
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
Session(app)

db = SQLAlchemy(app)

api.add_resource(Lands, '/land')
api.add_resource(Land, '/land/<int:id>')
#api.add_resource(Projects, '/project')
#api.add_resource(Project, '/project/<int:id>')
api.add_resource(Sellers, '/seller')
api.add_resource(Seller, '/seller/<int:id>')
api.add_resource(Appointments, '/appointment')
api.add_resource(Appointment, '/appointment/<int:app_id>')
api.add_resource(Common, '/common')
api.add_resource(Caveats, '/caveat')
api.add_resource(Caveat, '/caveat/<int:code>')
api.add_resource(Landtitles, '/landtitle')
api.add_resource(Landtitle, '/landtitle/<int:land_title_no>')
api.add_resource(Procedures, '/procedure')
api.add_resource(Procedure, '/procedure/<int:buy_code>')
api.add_resource(Locations, '/location')
api.add_resource(Location, '/location/<int:plot_id>')
api.add_resource(Buyers, '/buyer')
api.add_resource(Buyer, '/buyer/<int:id>')
api.add_resource(Agreements, '/agreement')
api.add_resource(Agreement, '/agreement/<int:agreement_code>')
api.add_resource(Buy_sell_transactions, '/buy_sell_transaction')
#api.add_resource(Projects, '/projects')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    #token = db.Column(db.String(100))
    #admin = db.Column(db.Boolean)
    #---hashing password below added---
    #password = db.Column(db.String(128))

    #---below already present------
    def __init__(self, username, password, email):
        self.username = username
        self.password = generate_password_hash(password)
        self.email = email
        #----hashing password below added above already present---

    #@property
    #def unhashed_password(self):

    #    raise AttributeError('cannot view unhased password')

    #@unhashed_password.setter
    #def unhashed_password(self,unhashed_password):
    #    self.password = generate_password_hash(unhashed_password )
#@property
#def unhashed_password(self):
#     raise AttributeError('cannot view unhased password')

#@unhashed_password.setter
#def unhashed_password(self,unhashed_password):
#      self.password = generate_password_hash(unhashed_password )

# Routes

#@app.route('/favicon.ico')
#def favicon():
#    return send_from_directory(os.path.join(app.root_path, 'static'),
#                          'favicon.ico',mimetype='image/vnd.microsoft.icon')


@app.route('/', methods=['GET','POST'])
def index():
    #full_name1 = os.path.join(app.config['UPLOAD_FOLDER'], 'case1.jpg')
    #return render_template("index.html", user_image1=full_name1)
    if session.get('logged_in'):
        return render_template('home.html')
    else:
        return render_template('index.html', message="Hello!")
        #return render_template('index.html', message=<a href="/static/index2.html">/static/index2.html</a>")

@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            db.session.add(User(username=request.form['username'], password=request.form['password'], email=request.form['email']))
            db.session.commit()
            return redirect(url_for('login'))
        except:
            return render_template('index.html', message="User Already Exists or Error occured")
    else:
        return render_template('register.html')

#@app.route('/favicon.ico')
#def favicon():
#    return send_from_directory(os.path.join(app.root_path, 'static'),
#                          'favicon.ico',mimetype='image/vnd.microsoft.icon')

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        #u = request.form['username']
        #p = request.form['password']
        username = request.form['username']
        password = request.form['password']
        data = User.query.filter_by(username=username).first()
        #data = User.query.filter_by(username=u, password=p).first()
        #if data and check_password_hash(data.password, password):
        if data and check_password_hash(data.password, password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('index.html', message="You are not admin")
@app.route('/adminlogin/', methods=['GET', 'POST'])
def adminlogin():
  #below added# 
  ##username = request.form['username']
  ##password = request.form['password']
  #owner = User.query.filter_by(email=email,password=password,admin=True).first()
  ##owner = User.query.filter_by(username=username,password=password,admin=True).first()
  ##if owner:
          #flash("Username or password is wrong")
          #return   redirect(url_for('home'))
     #else: 

          #login_user(owner)
          #flash("Welcome")
          #return   redirect(url_for('get_signin_admin'))   
  #above added #

    if request.method == 'GET':
        return render_template('adminlogin.html')
         #return render_template('static/index2.html')
    else:
        u = request.form['username']
        p = request.form['password_hash']
        data = User.query.filter_by(username=u, password=p).first()
        if data is not None:
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('index.html', message="Incorrect Details")
     # below case currently added #
        ##else:
       ##flash("You are not Admin")
          #return redirect(url_for('index'))
     


#rows = db.session.query(User.doctor==0,User.admin==0).count()
#appoint_rows = db.session.query(Appointments).count()
#owner = User.query.filter_by(email=current_user.email,password=current_user.password,admin=True).first()
#    if not owner:
#        flash("The logins provided is not an admin!")
#        return redirect(url_for('home'))
     
#    else:

#          return render_template('admin_dash.html' ,rows = rows )
# above added #

@app.route('/index2/', methods=['GET', 'POST'])
def index2():
    #if session.get('logged_in') and admin=True:
    if session.get('logged_in'):
        return render_template('home.html')
    else:
        #return redirect(url_for(adminlogin))
        return render_template('adminlogin.html', message="Hello!")

#User Class
class User2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(255), nullable=False)
    lname = db.Column(db.String(255), nullable=False)
    email2 = db.Column(db.String(255), nullable=False)
    username2 = db.Column(db.String(255), nullable=False)
    edu = db.Column(db.String(255), nullable=False)
    password2 = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f'User2("{self.id}","{self.fname}","{self.lname}","{self.email2}","{self.username2}","{self.edu}","{self.password2}","{self.status}")'

    #---hashing password below added---
    #password = db.Column(db.String(128))
    
#create table
#db.create_all()
#main index
#@app.route('/')
#def index():
#    return render_template('index.html',title="")

#admn login
#@app.route('/admin/',methods=['POST','GET'])
#def adminIndex():
#    return render_template('admin/index.html',title='Admin login')

#User register
@app.route('/user_signup/',methods=['POST','GET'])
def user_signup():
  if request.method == 'POST':
      #get all field input name
      fname=request.form.get('fname')
      lname=request.form.get('lname')
      email2=request.form.get('email')
      username2=request.form.get('username')
      edu=request.form.get('edu')
      password2=request.form.get('password')
   
      #check whether all the field are filled
      if fname==" " or lname==" " or email2==" " or username2==" " or edu==" " or password2==" ":
        flash('please fill all the field','danger')
        return redirect(url_for(user_signup))
        #return render_template('user_signup/signup.html')
      else:
          hash_password=bcrypt.generate_password_hash(password2)
          user2=User2(fname=fname,lname=lname,email2=email2,password2=hash_password,edu=edu,username2=username2)
          db.session.add(user2)
          db.session.commit()
          return('successfully added to the database')
      #else:
         #is_email=User().query.filter_by(email=email).first()
         #if is_email:
            #flash('email already exist','danger')
            #return redirect(url_for(user_signup/index))
            #return render_template('user_signup/index.html')
  else:
    #return redirect(url_for(user_signup/signup))
    return render_template('user_signup/signup.html')

#User login
@app.route('/user_login/',methods=['POST','GET'])
def user_login():
    if request.method=="POST":

      #check admin approval
      is_approve=User.query.filter_by()
      # enter nme of the field
      email2=request.form.get('email')
      password2=request.form.get('password')
      #check user exists in this email or not
      users=User2().query.filter_by(email2=email2).first()
      if users and bcrypt.check_password_hash(users.password2,password2):
          #check admin approve your account or not
          is_approve=User2.query.filter_by(id=users.id).first()
          #first return is_approve
          #retrun f'{is_approve.status}'
          if is_approve.status == 0: 
               flash(' Email and Password','Not okay')
               #return redirect(url_for(user_login/index))
               return render_template('user_login/home.html')
          else:
              session['user_id']=users.id
              session['username2']=users.username2
              flash('Login success','okay')
              #return redirect(url_for(user_login/index))
              return render_template('user_login/home.html')
       #else:
       #    flash('invalid email and password','danger')
       #    return redirect('/user/')
    else:
     return render_template('user_login/home.html')

@app.route('/index3/', methods=['GET', 'POST'])
def index3():
     return render_template('user_login/index3.html')
    #if session.get('logged_in') and admin=True:
    #if session.get('logged_in'):
     #   return render_template('home.html')
    #else:
        #return redirect(url_for(adminlogin))
        #return render_template('adminlogin.html', message="Hello!")

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['logged_in'] = False
    return redirect(url_for('index'))
@app.route('/logout2', methods=['GET', 'POST'])
def logout2():
    session['logged_in'] = False
    return render_template('user_login/index.html')

if(__name__ == '__main__'):
    app.secret_key = "ThisIsNotASecret:p"
    db.create_all()
    app.run(debug= True,host ="localhost")