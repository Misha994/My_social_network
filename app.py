from os import path, chdir, unlink, rename, listdir, makedirs
from glob import glob
from random import randint

from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from flask.ext.uploads import UploadSet, configure_uploads, IMAGES, AUDIO
from ast import literal_eval


from form.loginForm import LoginForm
from form.registerForm import RegisterForm, UpdateForm, UpdatePasswordForm
from form.profileForm import ProfileForm, ProfileFormDate

app = Flask(__name__)

photos = UploadSet('photos', IMAGES)
musices = UploadSet('musices', AUDIO)
basedir = path.abspath(path.dirname(__file__))
app.config['SECRET_KEY'] = 'Secret_key!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path.join(basedir, 'myApp.sqlite')
app.config['UPLOADED_PHOTOS_DEST'] = path.join(basedir, 'static/img')
app.config['UPLOADED_MUSICES_DEST'] = path.join(basedir, 'static/music')
configure_uploads(app, (photos,musices))
db = SQLAlchemy(app)
socketio = SocketIO(app)
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
    bday = db.Column(db.Integer, nullable=True)
    sex = db.Column(db.String(20), nullable=False)
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
    user_id = db.Column(db.Integer, nullable=False)

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

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(300))

class Music(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(300))

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500))
    owner = db.Column(db.String(100))

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
    users = User.query.all()
    profile = Profile.get_by_user_id(current_user.id)
    contacts = Contact.get(current_user.id)
    photo = Photo.query.filter_by(owner_id=current_user.id).first()
    photos = Photo.query.all()
    return render_template('profile.html',user=current_user,profile=profile,contacts=contacts,users=users,photo=photo,photos=photos)

@app.route('/contact')
@login_required
def all_contact():
    all_users = User.query.all()
    contacts = Contact.get(current_user.id)
    profile = Profile.get_by_user_id(current_user.id)
    photos = Photo.query.all()
    photo = Photo.query.filter_by(owner_id=current_user.id).first()
    users = []
    for user in all_users:
        for contact in contacts:
            if (user.id == contact.user_id):
                break
        else:
            users.append(user)
    return render_template('contact.html',users=users,contacts=contacts,photos=photos,photo=photo,profile=profile,user=current_user)

@app.route('/friends')
@login_required
def friends():
    users = User.query.all()
    profile = Profile.get_by_user_id(current_user.id)
    contacts = Contact.get(current_user.id)
    photo = Photo.query.filter_by(owner_id=current_user.id).first()
    photos = Photo.query.all()
    return render_template('friends.html',user=current_user,profile=profile,contacts=contacts,users=users,photo=photo,photos=photos)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/update', methods=['GET', 'POST'])
@login_required
def user_update():
    user = User.get_by_id(current_user.id)
    profile = Profile.get_by_user_id(current_user.id)
    update_form = UpdateForm()
    update_Password = UpdatePasswordForm()
    photo = Photo.query.filter_by(owner_id=current_user.id).first()
    form = RegisterForm()
    if request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
    if request.method == 'POST' and update_form.validate_on_submit():
        user.username=form.username.data
        user.email=form.email.data
        db.session.add(user)
        db.session.commit()
    if request.method == 'POST' and update_Password.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user.password=hashed_password
        db.session.add(user)
        db.session.commit()
    if request.method == 'POST' and 'photo' in request.files:
        filename = photos.save(request.files['photo'])
        directory = path.join(basedir, 'static/img')
        chdir(directory)
        for f in listdir():
            if f == filename:
                f_name, f_ext = path.splitext(f)
                f_name = str(current_user.id)
                new_name = '{}{}'.format(f_name,f_ext)
                rename(f,new_name)
                new_photo = Photo(owner_id=current_user.id, filename=new_name)
                db.session.add(new_photo)
                db.session.commit()
                return redirect(url_for('profile'))
    return render_template('profile_update.html', form=form, user=current_user, photo=photo, profile=profile)

@app.route('/profile/<user_id>/photo')
@login_required
def change_photo(user_id):
    photo = Photo.query.filter_by(owner_id=user_id).first()
    directory = path.join(basedir, 'static/img')
    chdir(directory)
    files=glob(photo.filename)
    for filename in files:
        unlink(filename)
    db.session.delete(photo)
    db.session.commit()
    return redirect('/update')

@app.route('/extend_profile', methods=['GET','POST'])
@login_required
def extend_profile():
    form = ProfileForm()
    form_Date = ProfileFormDate()
    profile = Profile.get_by_user_id(current_user.id)
    photo = Photo.query.filter_by(owner_id=current_user.id).first()
    if request.method == 'GET' and profile:
        form.sex.data = profile.sex
        form.city.data = profile.city
    if request.method == 'POST' and form.validate_on_submit() and profile:
        profile.sex = form.sex.data
        profile.city = form.city.data
        db.session.add(profile)
        db.session.commit()
    if request.method == 'POST' and form_Date.validate_on_submit() and profile:
        profile.bday = form.bday.data
        db.session.add(profile)
        db.session.commit()
    if request.method == 'POST' and form.validate_on_submit() and not profile:
        add_profile = Profile(user_id=current_user.id,
                              bday=form.bday.data,
                              sex=form.sex.data,
                              city=form.city.data)
        db.session.add(add_profile)
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('extend_profile.html', form=form, photo=photo, profile=profile, user=current_user)

@app.route('/<user_id>')
@login_required
def contact_info(user_id):
    users = User.query.all()
    user = User.get_by_id(user_id)
    photo = Photo.query.filter_by(owner_id=user_id).first()
    photos = Photo.query.all()
    profile = Profile.get_by_user_id(user_id)
    contacts = Contact.get(user_id)
    return render_template('contact_info.html', user=user, profile=profile, contacts=contacts, users=users, photos=photos, photo=photo)

@app.route('/contact/<user_id>/add', methods=['GET'])
@login_required
def add_contact(user_id):
    contact = Contact(owner_id = current_user.id,user_id = user_id)
    db.session.add(contact)
    db.session.commit()
    return redirect('profile')

@socketio.on('my event')
def handle_my_custom_event(json):
    json_message = literal_eval(str(json))
    massage = History(message=json_message["message"], owner=current_user.username)
    db.session.add(massage)
    db.session.commit()
    socketio.emit('my response', json)

@app.route('/messages')
@login_required
def messages():
    profile = Profile.get_by_user_id(current_user.id)
    messages = History.query.all()
    messages.reverse()
    photo = Photo.query.filter_by(owner_id=current_user.id).first()
    return render_template('messages.html', user=current_user, messages=messages,profile=profile,photo=photo)


@app.route('/profile/<user_id>/delete')
def user_del(user_id):
    user = User.get_by_id(user_id)
    contact = Contact.query.filter_by(id=user_id).first()
    profile = Profile.get_by_user_id(current_user.id)
    if profile:
        db.session.delete(profile)
        db.session.commit()
    if contact:
        db.session.delete(contact)
        db.session.commit()
    db.session.delete(user)
    db.session.commit()
    return redirect('/')

@app.route('/contact/<user_id>/delete')
@login_required
def contact_del(user_id):
    contact = Contact.query.filter_by(id=user_id).first()
    db.session.delete(contact)
    db.session.commit()
    return redirect('/profile')

@app.route('/musices', methods=['GET', 'POST'])
@login_required
def music():
    users = User.query.all()
    profile = Profile.get_by_user_id(current_user.id)
    contacts = Contact.get(current_user.id)
    photo = Photo.query.filter_by(owner_id=current_user.id).first()
    photos = Photo.query.all()
    all_musices = Music.query.all()
    if request.method == 'POST' and 'music' in request.files:
        filename = musices.save(request.files['music'])
        directory = path.join(basedir, 'static/music/')
        chdir(directory)
        for f in listdir():
            if f == filename:
                if not str(current_user.id) in listdir():
                    makedirs(str(current_user.id))
                    prevDir = directory+filename
                    newDir = directory+str(current_user.id)+'/'+filename
                    rename(prevDir,newDir)
                    new_music = Music(owner_id=current_user.id, filename=filename)
                    db.session.add(new_music)
                    db.session.commit()
                    return redirect(url_for('music'))
                elif filename in listdir(directory+str(current_user.id)):
                    a = randint(1,10)
                    prevDir = directory+filename
                    newDir = directory+str(current_user.id)+'/'+str(a)+filename
                    rename(prevDir,newDir)
                    new_music = Music(owner_id=current_user.id, filename=str(a)+filename)
                    db.session.add(new_music)
                    db.session.commit()
                    return redirect(url_for('music'))
                else:
                    prevDir = directory+filename
                    newDir = directory+'/'+str(current_user.id)+'/'+filename
                    rename(prevDir,newDir)
                    new_music = Music(owner_id=current_user.id, filename=filename)
                    db.session.add(new_music)
                    db.session.commit()
                    return redirect(url_for('music'))
    return render_template('musices_list.html',user=current_user,profile=profile,contacts=contacts,users=users,photo=photo,photos=photos,musices=all_musices)

@app.route('/profile/<filename>/music')
@login_required
def delete_music(filename):
    music = Music.query.filter_by(owner_id = current_user.id, filename=filename).first()
    directory = path.join(basedir, 'static/music/'+ str(current_user.id))
    chdir(directory)
    unlink(filename)
    db.session.delete(music)
    db.session.commit()
    return redirect(url_for('music'))

@app.route('/<user_id>music')
@login_required
def contact_music(user_id):
    users = User.query.all()
    user = User.get_by_id(user_id)
    photo = Photo.query.filter_by(owner_id=user_id).first()
    photos = Photo.query.all()
    profile = Profile.get_by_user_id(user_id)
    contacts = Contact.get(user_id)
    musices = Music.query.all()
    return render_template('contact_music.html', user=user, profile=profile, contacts=contacts, users=users, photos=photos, photo=photo,musices=musices)

if __name__ == '__main__':
    db.create_all()
    socketio.run(app)
    app.run()