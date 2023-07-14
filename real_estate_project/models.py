from database import db, app
from flask_login import UserMixin, login_manager, LoginManager
from flask_user import roles_required
from flask_wtf import FlaskForm
from wtforms import Form, StringField, validators, PasswordField, IntegerField, FloatField, FileField, SelectField, RadioField
from wtforms.validators import DataRequired, Email, NumberRange, Optional, InputRequired



login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    # Load the user object from the database based on the user ID
    # Replace this with your actual logic to retrieve the user from the database
    user = User.query.get(int(user_id))
    return user

'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Forms
# Define a form using WTForms library
class MyForm(Form):
    name = StringField('Name', validators=[validators.DataRequired()])
    
class PropertyForm(FlaskForm):
    name = StringField('Property name', validators=[DataRequired()])
    size = FloatField('Size', validators=[DataRequired(), NumberRange(min=0)])
    bed = IntegerField('Bedrooms', validators=[DataRequired(), NumberRange(min=0)])
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0)])
    bath = IntegerField('Bathrooms', validators=[DataRequired(), NumberRange(min=0)])
    address = StringField('Location', validators=[DataRequired()])
    category_id = SelectField('Property Type', coerce=int, validators=[InputRequired()])
    status = RadioField('Sale Status', choices=[('Sale', 'For Sale'), ('Rent', 'For Rent')], validators=[Optional()])
    image = FileField('Property Image')
    
# Define the form for registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

# Define the form for login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    properties = db.relationship('Property', backref='category', lazy=True)
    
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic', foreign_keys='User.role_id')

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    
    def has_roles(self, *roles):
        # Check if the user has any of the specified roles
        return self.role.name in roles
    
class Agent(db.Model):
    __tablename__ = 'agents'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    designation = db.Column(db.String(100), nullable=False)
    twitter_handle = db.Column(db.String(100))
    instagram_handle = db.Column(db.String(100))
    facebook_handle = db.Column(db.String(100))
    image = db.Column(db.String(100))



class CustomLoginForm(FlaskForm):
    def validate(self):
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        # Check if the user has the 'admin' role
        user = User.query.filter_by(username=self.username.data).first()
        if user.role.name != 'admin':
            return False

        return True

class Property(db.Model):
    __tablename__ = 'properties'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    size = db.Column(db.String(20), nullable=False)
    bed = db.Column(db.Integer, nullable=False)
    bath = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(255))

with app.app_context():
    db.create_all()
# flask db init
# flask db migrate