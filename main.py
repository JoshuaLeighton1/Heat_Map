import data as D
import requests
from flask import Flask,  render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt

#initialize flask app
app = Flask(__name__)
page = requests.get("https://www.worldometers.info/coronavirus")
#configure flask
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C-heatmap.db'
#configure Bcrypt for passwords later
Bcrypt = Bcrypt(app)
#configure database
db = SQLAlchemy(app)
#CSRF token secret key
app.config['SECRET_KEY'] = 'thisIsTheKey'

#initialize LoginManager() that contains the code that lets the app and Flask work together
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

#create a user loader function
@login_manager.user_loader

def load_user(user_id):
    return User.query.get(int(user_id))
 
#create a User Table in our database using UserMixin
class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(20), nullable=False)
    surname = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False)


#create a Registration form for our signup Page using FlaskForm
class RegisterForm(FlaskForm):

    username = StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw ={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)], render_kw={"placeholder":"Password"})
    name = StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw ={"placeholder": "First name"})
    surname = StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw ={"placeholder": "Lastname"})
    email = StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw ={"placeholder": "Email address"})
    submit = SubmitField("Register")

    #create a function to check if the username already exists
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username= username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one")

#create a LoginForm for our Login page
class LoginForm(FlaskForm):

    username = StringField('Username',validators=[InputRequired(),Length(min=4, max =20)], render_kw ={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(),Length(min=4,max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")



#create route for home page
@app.route('/', methods=["GET","POST"])
def home():
    obj = D.getData(page)
    obj1 = obj.scrape()
    cont_data = obj1[1]
    data_frame = obj1[2]
    all_data = obj1[0]
    country_data = obj1[3]

    print(User.query.all())
   
    if request.method == "GET":
        return render_template('home.html', country = country_data)
    return render_template('home.html', country = country_data)

#create a route for the sign up page
@app.route('/signUp', methods =['GET', 'POST'])
def register():

    form = RegisterForm()
    
    if form.validate_on_submit():
        pasw = form.password.data
        hashed_password = Bcrypt.generate_password_hash(pasw).decode('utf-8')
        new_user = User(username= form.username.data, password=hashed_password, name =form.name.data, surname =form.surname.data, email = form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/Login')

    return render_template('signUp.html', form = form)

#create route for Login page
@app.route('/Login', methods=["GET","POST"])
def login():
    
    form = LoginForm()
    #check if user exists
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if Bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                #open dashboard if username + password successful
                return redirect(url_for('dashboard'))
    #else just render login page
    return render_template('Login.html', form = form)

#create route for dashboard
@app.route('/dashboard', methods =['GET', 'POST'])
@login_required
def dashboard():
    
    return render_template('dashboard.html')

#create a log out route, just redirects to index page
@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True) 