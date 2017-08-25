import os.path

from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from form.loginForm import LoginForm
from form.registerForm import RegisterForm
from form.profileForm import ProfileForm

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'myApp.sqlite')
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=False)
    email = db.Column(db.String(50), unique=False)
    password = db.Column(db.String(80))

    @staticmethod
    def get_by_id(user_id):
        try:
            user = User.query.get(user_id)
            return user
        except Exception:
            return None

class Profile(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    city = db.Column(db.String(20), unique=False)

    @staticmethod
    def get_by_id(user_id):
        try:
            profile = Profile.query.get(user_id)
            return profile
        except Exception:
            return None

    @staticmethod
    def get_by_user_id(user_id):
        try:
            profile = Profile.query.filter_by(user_id=user_id).first()
            return profile
        except Exception:
            return None

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False, unique=True)

    @staticmethod
    def create(owner_id, user_id):
        contact = Contact(owner_id=owner_id,
                          user_id=user_id)
        db.session.add(contact)
        db.session.commit()

    @staticmethod
    def get(owner_id):
        contacts = Contact.query.filter_by(owner_id=owner_id)
        return contacts

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('profile'))
        return '<h1>Invalid username or password</h1>'
    return render_template('index.html', form=form)

@app.route('/create_profile', methods=['GET', 'POST'])
def create_profile():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user has been created!</h1>'
    return render_template('create_profile.html', form=form)

@app.route('/profile')
@login_required
def profile():
    profile = Profile.get_by_user_id(current_user.id)
    contacts = Contact.get(current_user.id)
    return render_template('profile.html', user=current_user, profile=profile, contacts=contacts)

@app.route('/contact')
@login_required
def contact():
    users = User.query.all()
    contacts = Contact.get(current_user.id)
    users = [user for user in users if not user.id == int(current_user.id)]
    return render_template('contact.html', users=users, contacts=contacts)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile/update', methods=['GET', 'POST'])
@login_required
def user_update():
    user = User.get_by_id(current_user.id)
    form = RegisterForm()
    if request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.password.data = user.password
    if request.method == 'POST' and form.validate_on_submit():
        user.username=form.username.data
        user.email=form.email.data
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user.password=hashed_password
        db.session.add(user)
        db.session.commit()
    return render_template('profile_update.html', form=form)

@app.route('/profile/extend_profile', methods=['GET','POST'])
@login_required
def extend_profile():
    form = ProfileForm()
    if request.method == 'POST' and form.validate_on_submit():
        profile = Profile(user_id=current_user.id, city=form.city.data)
        db.session.add(profile)
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('extend_profile.html', form=form)

@app.route('/contact/<user_id>')
@login_required
def contact_user(user_id):
    user = User.get_by_id(user_id)
    profile = Profile.get_by_user_id(user_id)
    return render_template('profile.html', user=user, profile=profile)

@app.route('/contact/<user_id>/add', methods=['GET'])
@login_required
def add_contact(user_id):
    contact = Contact(owner_id = current_user.id,user_id = user_id)
    db.session.add(contact)
    db.session.commit()
    return redirect('profile')


if __name__ == '__main__':
    db.create_all()
    app.run()