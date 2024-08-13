from flask import Flask, render_template,url_for,redirect,request,flash,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os


UPLOAD_FOLDER = 'static/uploads'
Allowed_Extensions = {'png','jpg','jpeg'}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_data.db'
app.config['SECRET_KEY']='mysecretkey'
app.config['UPLOAD_FOLDER']=  UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  
db=SQLAlchemy(app)
app.app_context().push()
bycrypt = Bcrypt(app)
login_manager = LoginManager(app) 


class User(db.Model,UserMixin): #create a table
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False,unique=True)
    # nulltable = False means cannot be emptied 
    # #unique = True means cannot be repeated
    password = db.Column(db.String(80),nullable=False)
    
class LoginForm(FlaskForm): 
    username = StringField('username',validators=[InputRequired(),Length(min=3,max=20)], 
                           render_kw={"placeholder": "Username"})
    password = PasswordField('password',validators=[InputRequired(),Length(min=5,max=20)], 
                             render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')
    
    
class RegisterForm(FlaskForm): #create a form
    username = StringField('username',validators=[InputRequired(),Length(min=3,max=20)], 
                           render_kw={"placeholder": "Username"})
    password = PasswordField('password',validators=[InputRequired(),Length(min=5,max=20)], 
                             render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')
    
    def validate_username(self,username): #check if username already exists
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username is already taken. Please choose a different one.')    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/') #home page
def home():
        return render_template('home.html')

@app.route('/login',methods=['Get', 'Post'])#login page
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bycrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('index'))
    
    return render_template('login.html',form=form)


@app.route('/logout',methods=['Get','Post'])#logout page
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/register',methods=['Get', 'Post'])#register page
def register():
    form=RegisterForm()
    if form.validate_on_submit(): #if the form is submitted, create hashed password and add to the database
        hashed_password = bycrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,password=hashed_password)
        db.session.add(new_user) #add to the database
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html',form=form)    

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Allowed_Extensions

def create_user_folder(username):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    return user_folder

@app.route('/index', methods=['GET', 'POST'])  # Index page
@login_required  # Login required to access this page
def index():
    username = current_user.username
    user_folder = create_user_folder(username)
    # Get list of uploaded files from the user's upload directory
    uploaded_files = os.listdir(user_folder)
    return render_template('index.html', username=username, uploaded_files=uploaded_files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'uploadFile' not in request.files:
        flash('No file part')
        return redirect(request.url)
    files = request.files.getlist('uploadFile')
    user_folder = create_user_folder(current_user.username)
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(user_folder, filename))
            print('File(s) successfully uploaded')
        else:
            print('Invalid file format')
    return redirect(url_for('index'))


if __name__ == '__main__':#run the app
    app.run(debug=True)
    
    