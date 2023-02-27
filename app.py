from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_manager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
#Creating the database instance 
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
#connecting the app file to the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'Ogodoremmanuel'

login_manager = login_manager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.column(db.Integer, primary_key=True) #the user identity coloumn in my database
    username = db.Coloumn(db.String(20), nullable=False, unqiue = True)  #users username and password coloumn
    password = db.Coloumn(db.String(80), nullable=False)
#write in terminal
#form app , import db to import all db files
#db.create_all() to create the database table

class Registrationforms(Flaskform):
    username = StringField(validators=[InputRequired(), length(min=4, max=16)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(),length(min=4, max=16)], render_kw={"placeholder": "password"})

    submit = SubmitField("register")


class loginforms(Flaskforms):
    username = StringField(validators=[InputRequired(),length(min=4, max=16)], render_kw={"placeholder": "username"})
    password =PasswordField(validators=[InputRequired(),length(min=4, max=16)], render_kw={"placeholder": "password"})


    submit = SubmitField("login")

def validate_username(self, username):
    existing_user_username = User.query.filter_by(username=username.data).first()

    if existing_user_username: raise ValidationError("This username already exist, Please choose another one.")


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=loginforms()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_harsh(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def loogout():
    logout_user()
    return redirect(url_for('login'))

    
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')



@app.route('/register',methods=['GET', 'POST'])
def register():
    form=Registrationforms()

    if form.validate_on_submit():
        hashed_password = Bcrypt.generate_password_harsh(form.password.data)
        new_user=User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)
  


if __name__ == '__main__':
    app.run(debug=True)

