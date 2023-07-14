from database import db, app
from flask_login import UserMixin, login_manager, LoginManager
from flask_user import roles_required
from flask_wtf import FlaskForm


login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    # Load the user object from the database based on the user ID
    # Replace this with your actual logic to retrieve the user from the database
    user = User.query.get(int(user_id))
    return user

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
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    location = db.Column(db.String, nullable=True)

with app.app_context():
    db.create_all()
