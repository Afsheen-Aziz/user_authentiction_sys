from flask import Flask, render_template, flash, request,redirect,url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

# Create a Flask Instance
app = Flask(__name__,template_folder='C:\\Users\\HP\\OneDrive\\Desktop\\flaskwebappv2\\templates')
#Add Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Secret Key
app.config['SECRET_KEY']="ihatecats"
# Initialize Database
db = SQLAlchemy(app)
migrate = Migrate(app,db)

# Flask Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))
    
# Create a Login Page
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # Check the hash
            if check_password_hash(user.password_hash,form.password.data):
                login_user(user)
                flash("Login Successful")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password- Try Again")
        else:
            flash("User doesn't exist")
            
    return render_template('login.html', form=form)

# Create Login Form
class LoginForm(FlaskForm):
    username = StringField("Userame", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

#Create logout page
@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out!")
    return redirect(url_for('login'))

# Create Dashboard page
@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    form = AddForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("Updated Successfully")
            return render_template("dashboard.html",form=form,name_to_update=name_to_update)
        except:
            flash("Error.. Try Again")
            return render_template("dashboard.html",form=form,name_to_update=name_to_update)
    else:
        return render_template("dashboard.html",form=form,name_to_update=name_to_update, id=id)
    return render_template('dashboard.html')


# Create Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    # Password
    password_hash = db.Column(db.String(128))
    
    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute!')
    
    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)
        
    def verify_password(self,password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return '<Name %r>' % self.name
    
class UserInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(500), nullable=False)
    phone = db.Column(db.String(100), nullable=False, unique=True)
    gender = db.Column(db.String(20), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Create a string
    def __repr__(self):
        return '<Name %r>' % self.name



class PasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField('Password',validators=[DataRequired()])
    submit = SubmitField("Submit")
    
    
 #Create a Form Class
class NamerForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Delete database record
@app.route('/delete/<int:id>',methods=['GET','POST'])
def delete(id):
    user_to_delete= Users.query.get_or_404(id)
    name = None
    form = AddForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User Deleted Successfully")
        our_users = Users.query.order_by(Users.date_added)     
        return render_template("add_user.html", form=form, name=name, our_users=our_users)
        
    except:
        flash("Error deleting")
        return render_template("add_user.html", form=form, name=name, our_users=our_users)

    
    
class AddForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email Address", validators=[DataRequired()])
    password_hash = PasswordField("Password",validators=[DataRequired(), EqualTo('password_hash2', message='Passwords must match!')])
    password_hash2 = PasswordField('Confirm Password',validators=[DataRequired()])
    submit = SubmitField("Submit")
    
# Update database Record
@app.route('/update/<int:id>',methods=['GET','POST'])
def update(id):
    form = AddForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("Updated Successfully")
            return render_template("update.html",form=form,name_to_update=name_to_update)
        except:
            flash("Error.. Try Again")
            return render_template("update.html",form=form,name_to_update=name_to_update)
    else:
        return render_template("update.html",form=form,name_to_update=name_to_update, id=id)
    
class UserForm(FlaskForm):
    firstname = StringField("First Name", validators=[DataRequired()])
    lastname = StringField("Last Name", validators=[DataRequired()])
    age = IntegerField("Age", validators=[DataRequired()])
    address = StringField("Address", validators=[DataRequired()])
    phone = StringField("Phone Number",validators=[DataRequired()])
    gender = StringField("Gender", validators=[DataRequired()])
    submit = SubmitField("Submit")

        
def create_db():
    with app.app_context():
        db.create_all()
    print('Created Database!')


    
# Create a route decorator
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/user/<name>')
def user(name):
   return render_template("user.html",name=name)

#Create Custom Error Pages
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404
 
#Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500
 
# Create Form Page
@app.route('/form', methods=['GET','POST'])
def name():
    name = None
    form= NamerForm()
    #Validate Form
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("Form submitted successfully!")
    return render_template("name.html",name=name,form=form)

@app.route('/user/add', methods=['GET','POST'])
def add_user():
    name = None
    form = AddForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hash password
            hashed_pw = generate_password_hash(form.password_hash.data, "scrypt")
            user = Users(username=form.username.data,name=form.name.data, email=form.email.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        form.username.data =''
        form.password_hash.data = ''
        flash("User Added Successfully")
    our_users = Users.query.order_by(Users.date_added)  
            
    return render_template("add_user.html", form=form, name=name, our_users=our_users)

@app.route('/user/info', methods=['GET','POST'])
def userinfo():
    name = None
    form = UserForm()
    #Validate Form
    if form.validate_on_submit():
        user = UserInfo.query.filter_by(phone=form.phone.data).first()
        if user is None:
            user = UserInfo(firstname=form.firstname.data,lastname=form.lastname.data,age=form.age.data,address=form.address.data,phone=form.phone.data,gender=form.gender.data)
            db.session.add(user)
            db.session.commit()
        name = form.firstname.data
        form.firstname.data = ''
        form.lastname.data = ''
        form.age.data = ''
        form.address.data = ''
        form.phone.data = ''
        form.gender.data = ''
        flash("User Information Added")
    user_info = UserInfo.query.order_by(UserInfo.date_added)
    return render_template("userinfo.html", form=form,name=name,user_info=user_info)


# Create Password test Page
@app.route('/test_pw', methods=['GET','POST'])
def test_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None
    form= PasswordForm()
    
    #Validate Form
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        # Clear the form
        form.email.data = ''
        form.password_hash.data = ''
        
        # Lookup user by email address
        pw_to_check = Users.query.filter_by(email=email).first()
        
        # Check Hashed Password
        passed = check_password_hash(pw_to_check.password_hash, password)
    
    return render_template("test_pw.html",email=email,password=password,pw_to_check = pw_to_check, passed = passed,form=form)