from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.fields.html5 import DateField
from wtforms.validators import Optional, Length, InputRequired

class ProfileForm(FlaskForm):
    bday = DateField('Bday', validators=[Optional()], format='%Y-%m-%d')
    sex = SelectField('Sex', validators=[Optional()], choices=[('Male', 'Male'), ('Female', 'Female')])
    city = StringField('Сity', validators=[Optional(), Length(min=2, max=20)])

class ProfileFormDate(FlaskForm):
    bday = DateField('Bday', validators=[InputRequired()], format='%Y-%m-%d')