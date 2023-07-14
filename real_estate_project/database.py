from flask import request, render_template, redirect, Flask, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import psycopg2
from werkzeug.utils import secure_filename
import os


app = Flask(__name__)
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}  # define allowed image file extensions
UPLOAD_FOLDER = 'static/images'  # set your upload folder path

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://boss:key@localhost:5432/realestatedb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'mysecretkey'

db = SQLAlchemy()
migrate = Migrate()

db.init_app(app)
migrate.init_app(app, db)

with app.app_context():
    db.create_all()