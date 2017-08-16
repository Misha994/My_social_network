from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length

class ProfileForm(FlaskForm):
    city = StringField('city', validators=[InputRequired(), Length(min=2, max=20)])
