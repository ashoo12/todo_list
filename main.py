from functools import wraps
from flask import Flask,render_template,redirect,url_for,request,flash,abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,PasswordField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,UserMixin,current_user,login_user

from sqlalchemy.orm import relationship,declarative_base
from werkzeug.security import generate_password_hash,check_password_hash



Base=declarative_base()
app=Flask(__name__)
app.app_context().push()
Bootstrap(app)
app.secret_key='aishadarvesh'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todos.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db=SQLAlchemy(app)


login_manager=LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def only_admin(function):
    @wraps(function)
    def decorated_function(*args,**kwargs):
        if current_user.id!=1:
            return abort(403)
        return function(*args,**kwargs)
    return decorated_function


#creating table for user sqlite data base
#User table is parent table
class User(UserMixin,db.Model):
    __tablename__="users"
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(250),nullable=False)
    email=db.Column(db.String(250),nullable=False)
    password=db.Column(db.String(250),nullable=False)
    task_list=relationship("Todo",back_populates="author")

#creating table for todolist sqlite data base
#this table is child table
class Todo(db.Model):
    __tablename__ = "todo_list"
    id=db.Column(db.Integer,primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "task_list" refers to the task_list property in the User class.
    author = relationship("User", back_populates="task_list")
    list = db.Column(db.String(250),nullable=False)
db.create_all()
all_lists=Todo.query.all()



#creating flask form for making task or todolist
class ListForm(FlaskForm):
      list=StringField(label="",validators=[DataRequired()],render_kw={"placeholder":"Type here.E.g Buy Bacon"})
      submit=SubmitField(render_kw={"style": "display:none;"})

#creating resgistration or sign up form for signing up on todolist website
class RegistrationForm(FlaskForm):
      email=StringField(label="Email",validators=[DataRequired()])
      password=PasswordField(label="Password",validators=[DataRequired()])
      name=StringField(label="Name",validators=[DataRequired()])
      submit=SubmitField(label="Sign Up")

#creating login form for logging in on todolist website
class LoginForm(FlaskForm):
      email=StringField(label="Email",validators=[DataRequired()])
      password=PasswordField(label="Password",validators=[DataRequired()])
      submit=SubmitField(label="Login")

#route and function for home page of todolist
@app.route('/',methods=['POST','GET'])
def home():
    form=ListForm()
    if form.validate_on_submit():
       flash("please login or signup first.")
    return render_template("index.html",form=form)

#route and function for signup
@app.route('/signup',methods=['POST','GET'])
def signup():
    registration_form=RegistrationForm()
    if registration_form.validate_on_submit():
        new_user=User(email=registration_form.email.data, name=registration_form.name.data, password=generate_password_hash(registration_form.password.data, method='pbkdf2:sha256', salt_length=8))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("my_list"))
    return render_template("signup.html",registration_form=registration_form)


# route and function for login
@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user=User.query.filter_by(email=login_form.email.data).first()
        if not user or not check_password_hash(user.password,login_form.password.data):
            flash("Email or Password is Incorrect!")
        else:
            login_user(user)
            return redirect(url_for("my_list"))
    return render_template("login.html", login_form=login_form)

#route and function for mylist or savedlist of todolist
@app.route('/mylist',methods=['POST','GET'])
def my_list():
    form = ListForm()
    if form.validate_on_submit():
        new_list = Todo(author=current_user,list=form.list.data)
        db.session.add(new_list)
        db.session.commit()
        return redirect(url_for("my_list"))
    user_tasks = Todo.query.filter_by(author=current_user).all()
    return render_template("input.html",user_tasks=user_tasks,form=form)

#route and function for deleting the task done.
@app.route('/delete/<int:id>',methods=['POST','GET'])
def delete(id):
    list_to_delete=Todo.query.get(id)
    db.session.delete(list_to_delete)
    db.session.commit()
    return redirect(url_for('home'))






if __name__=="__main__":
    app.run(debug=True)