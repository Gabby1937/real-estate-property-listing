from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
UPLOAD_FOLDER = 'static/images'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://boss:key@localhost:5432/realestatedb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'MVyH6mODK2CMHCvCGfVHXzxPe9E2Pmnap9tTzXabDttc1tOLY3f9Z3oYam-5PEPT'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()
