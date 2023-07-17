from flask import request, jsonify, render_template, redirect, Flask, flash, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_migrate import Migrate
import psycopg2, os, requests
from models import Category, Property, User, Role, Agent, PropertyForm, MyForm, AuthError, RegistrationForm, LoginForm
from database import app, db, migrate
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, LoginManager, login_user, logout_user, current_user
from flask_user import roles_required
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import Form, StringField, validators, PasswordField, IntegerField, FloatField, FileField, SelectField, RadioField
from wtforms.validators import DataRequired, Email, NumberRange, Optional, InputRequired
from functools import wraps
from jose import jwt
import json
from urllib.request import urlopen

app = Flask(__name__)


ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
UPLOAD_FOLDER = './static/img'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://boss:key@localhost:5432/realestatedb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'MVyH6mODK2CMHCvCGfVHXzxPe9E2Pmnap9tTzXabDttc1tOLY3f9Z3oYam-5PEPT'
csrf = CSRFProtect(app)
app.static_folder = 'static'

db.init_app(app)
migrate.init_app(app, db)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return user

with app.app_context():
    db.create_all()



def get_countries():
    url = "https://restcountries.com/v3.1/all"  # API endpoint for retrieving all countries
    response = requests.get(url)
    if response.status_code == 200:
        countries = response.json()
        return countries
    else:
        return None
    
# Configuration
# UPDATE THIS TO REFLECT YOUR AUTH0 ACCOUNT
AUTH0_DOMAIN = 'gabby.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'homes'


        
        
## Auth Header
def verify_decode_jwt(token):
    # GET THE PUBLIC KEY FROM AUTH0
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    
    # GET THE DATA IN THE HEADER
    unverified_header = jwt.get_unverified_header(token)
    
    # CHOOSE OUR KEY
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            # USE THE KEY TO VALIDATE THE JWT
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)
    
# # Verify and Decode the JWT
# decoded_payload = verify_decode_jwt(token)
# print(decoded_payload)

def get_token_auth_header():
## check if authorization is not in request
    if 'Authorization' not in request.headers:
        abort(401)
## get the token   
    auth_header = request.headers['Authorization']
    header_parts = auth_header.split(' ')
## check if token is valid
    if len(header_parts) != 2:
        abort(401)
    elif header_parts[0].lower() != 'bearer':
        abort(401) 
    return header_parts[1]

def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        jwt = get_token_auth_header()
        try:
            payload = verify_decode_jwt(jwt)
        except:
            abort(401)
        return f(payload, *args, **kwargs)
    return wrapper

# @app.route("/", methods=['GET', 'POST'])
# def index():
#     properties = Property.query.all()
#     categories = Category.query.all()
#     agents = Agent.query.all()
#     filtered_properties = properties  # Set the default value for filtered_properties
    
#     countries = get_countries()  # Retrieve the list of countries
#     user_id = session.get('user_id')  # Fetch the user_id from the session (update it based on your authentication mechanism)
#     user = User.query.get(user_id)  # Fetch the logged-in user from the database
#     user_role = user.role if user else None # Get the user's role
    
#     if countries is not None:
#         countries = sorted(countries, key=lambda c: c['name']['common'])
#     else:
#         300
    
#     form = MyForm(request.form)  # Create an instance of the form

#     if request.method == 'POST' and form.validate():
#         keyword = form.keyword.data
#         property_type = form.property_type.data
#         location = form.location.data

#         if keyword:
#             # Search by property name or location
#             filtered_properties = [p for p in filtered_properties if keyword.lower() in p.name.lower() or keyword.lower() in p.location.lower()]

#         if property_type and property_type != 'all':
#             # Search by property type (category)
#             filtered_properties = [p for p in filtered_properties if p.category_id == int(property_type)]

#         if location and location != 'all':
#             # Search by location
#             filtered_properties = [p for p in filtered_properties if location.lower() in p.location.lower()]

#         flash('Form submitted successfully')
#         return redirect(url_for('index'))  # Redirect to the index page after form submission

#     return render_template('index.html', form=form, properties=filtered_properties, categories=categories, category_icons=category_icons, countries=countries, agents=agents, user_role=user_role) #countries=countries)
#     #return render_template('index.html', properties=filtered_properties, categories=categories, countries=countries)


# @app.route("/", methods=['GET', 'POST'])
# def index():
#     # Check if user is authenticated
#     if 'user_id' not in session:
#         return redirect(url_for('login'))  # Redirect to the login page if user is not authenticated

#     properties = Property.query.all()
#     categories = Category.query.all()
#     agents = Agent.query.all()
#     filtered_properties = properties  # Set the default value for filtered_properties
    
#     countries = get_countries()  # Retrieve the list of countries
#     user_id = session.get('user_id')  # Fetch the user_id from the session (update it based on your authentication mechanism)
#     user = User.query.get(user_id)  # Fetch the logged-in user from the database
#     user_role = user.role if user else None # Get the user's role
    
#     if countries is not None:
#         countries = sorted(countries, key=lambda c: c['name']['common'])
#     else:
#         300
    
#     form = MyForm(request.form)  # Create an instance of the form

#     if request.method == 'POST' and form.validate():
#         keyword = form.keyword.data
#         property_type = form.property_type.data
#         location = form.location.data

#         if keyword:
#             # Search by property name or location
#             filtered_properties = [p for p in filtered_properties if keyword.lower() in p.name.lower() or keyword.lower() in p.location.lower()]

#         if property_type and property_type != 'all':
#             # Search by property type (category)
#             filtered_properties = [p for p in filtered_properties if p.category_id == int(property_type)]

#         if location and location != 'all':
#             # Search by location
#             filtered_properties = [p for p in filtered_properties if location.lower() in p.location.lower()]

#         flash('Form submitted successfully')
#         return redirect(url_for('index'))  # Redirect to the index page after form submission

#     return render_template('index.html', form=form, properties=filtered_properties, categories=categories, category_icons=category_icons, countries=countries, agents=agents, user_role=user_role)

@app.route("/", methods=['GET', 'POST'])
def index():
    properties = Property.query.all()
    categories = Category.query.all()
    agents = Agent.query.all()
    filtered_properties = properties  # Set the default value for filtered_properties
    
    countries = get_countries()  # Retrieve the list of countries
    user_id = session.get('user_id')  # Fetch the user_id from the session (update it based on your authentication mechanism)
    user = User.query.get(user_id)  # Fetch the logged-in user from the database
    user_role = user.role if user else None # Get the user's role
    
    if countries is not None:
        countries = sorted(countries, key=lambda c: c['name']['common'])
    else:
        300
    
    form = MyForm(request.form)  # Create an instance of the form

    if request.method == 'POST' and form.validate():
        keyword = form.keyword.data
        property_type = form.property_type.data
        location = form.location.data

        if keyword:
            # Search by property name or location
            filtered_properties = [p for p in filtered_properties if keyword.lower() in p.name.lower() or keyword.lower() in p.location.lower()]

        if property_type and property_type != 'all':
            # Search by property type (category)
            filtered_properties = [p for p in filtered_properties if p.category_id == int(property_type)]

        if location and location != 'all':
            # Search by location
            filtered_properties = [p for p in filtered_properties if location.lower() in p.location.lower()]

        flash('Form submitted successfully')
        return redirect(url_for('index'))  # Redirect to the index page after form submission

    return render_template('index.html', form=form, properties=filtered_properties, categories=categories, category_icons=category_icons, countries=countries, agents=agents, user_role=user_role) #countries=countries)


# Define the category_icons dictionary
category_icons = {
    'Apartment': 'icon-apartment.png',
    'Villa': 'icon-villa.png',
    'Home': 'icon-house.png',
    'Office': 'icon-housing.png',
    'Building': 'icon-building.png',
    'Townhouse': 'icon-neighborhood.png',
    'Shop': 'icon-condominium.png',
    'Garage': 'icon-luxury.png'
}

@app.route('/admin/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    return render_template('admin-properties.html', categories=categories)


# @app.route('/category/<int:category_id>/houses', methods=['GET'])
@app.route('/category/houses', methods=['GET'])
def category_houses(category_id):
    category = Category.query.get(category_id)
    properties = category.properties if category else []
    return render_template('property-type.html', category=category, properties=properties)



@app.route('/property', methods=['GET'])
def property_list():
    properties = Property.query.all()
    return render_template('property-list.html', properties=properties)


#-------------------------------------------------------------------------------------------------
# User Authentication
#-------------------------------------------------------------------------------------------------

# with app.app_context():
#     # Create a new admin user
#     admin_user = User(
#         username='gabby1937',
#         email='gabrieljohnson1937@gmail.com',
#         password=generate_password_hash('gj193752')
#     )
#     # Retrieve the role instance
#     role = Role.query.filter_by(name='admin').first()

#     # Assign the role to the user
#     admin_user.role = role

#     # Add the user to the database
#     db.session.add(admin_user)
#     db.session.commit()



@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Create a new User object and add it to the database
        new_user = User(username=username, email=email, password=hashed_password)
        
        # Assign a role to the user (e.g., "user" role)
        user_role = Role.query.filter_by(name='user').first()
        new_user.role = user_role
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
        except:
            db.session.rollback()
            flash('Error creating account. Please try again.', 'error')
        finally:
            db.session.close()
        
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


# @app.route("/login", methods=["GET", "POST"])
# def login():
#     form = LoginForm()

#     if request.method == "POST" and form.validate_on_submit():
#         username = form.username.data
#         password = form.password.data
        
#         # Check if the user exists in the database
#         user = User.query.filter_by(username=username).first()
#         if user and check_password_hash(user.password, password):
#             # Use Flask-Login's login_user function to log in the user
#             login_user(user)
#             flash('Login successful!', 'success')
            
#             # Redirect the user based on their role
#             if current_user.role.name == 'admin':
#                 flash('Login successful!', 'success')
#                 return redirect(url_for('admin_index'))
#             else:
#                 flash('Login successful!', 'success')
#                 return redirect(url_for('index'))
        
#         flash('Invalid username or password', 'error')
        
#     return render_template('login.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check if the user exists in the database
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Use Flask-Login's login_user function to log in the user
            login_user(user)
            flash('Login successful!', 'success')
            
            # Redirect the user based on their role
            if current_user.role.name == 'admin':
                flash('Login successful!', 'success')
                return redirect(url_for('admin_index'))
            else:
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
        
        flash('Invalid username or password', 'error')
        
    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    # Use Flask-Login's logout_user function to log out the user
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))


@app.route("/testimonial")
def testimonial():
    return render_template("testimonial.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/error")
def error():
    return render_template("error.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route('/search', methods=['POST'])
def search():
    properties = Property.query.all()
    categories = Category.query.all()
    filtered_properties = properties
    
    countries = get_countries()
    
    if countries is not None:
        countries = sorted(countries, key=lambda c: c['name']['common'])
    
    if request.method == 'POST':
        keyword = request.form.get('keyword')
        property_type = request.form.get('property_type')
        location = request.form.get('location')

        filtered_results = []  # Initialize a list to store the filtered results
        
        if keyword:
            # Search by property name or location
            filtered_properties_keyword = [p for p in filtered_properties if p.name and p.location and (keyword.lower() in p.name.lower() or keyword.lower() in p.location.lower())]
            filtered_results.append(filtered_properties_keyword)
            
        if property_type and property_type != 'all':
            # Search by property type (category)
            filtered_properties_type = [p for p in filtered_properties if p.category_id == int(property_type)]
            filtered_results.append(filtered_properties_type)
            
        if location and location != 'all':
            # Search by location
            filtered_properties_location = [p for p in filtered_properties if p.location and location.lower() in p.location.lower()]
            filtered_results.append(filtered_properties_location)
        
        # Merge the filtered results into a single list and remove duplicates
        merged_results = list(set([p for sublist in filtered_results for p in sublist]))
        
        return render_template('index.html', properties=merged_results, categories=categories, countries=countries, category_icons=category_icons)

    return render_template('index.html', properties=filtered_properties, categories=categories, countries=countries, category_icons=category_icons)


    
@app.route('/properties', methods=['GET', 'POST', 'PUT'])
@login_required
@roles_required('admin')
def add_property():
    form = PropertyForm()
    categories = Category.query.all()
    form.category_id.choices = [(category.id, category.name) for category in categories]
    


    if form.validate_on_submit():
        name = form.name.data
        size = form.size.data
        bed = form.bed.data
        price = form.price.data
        bath = form.bath.data
        location = form.address.data
        category_id = form.category_id.data
        status = form.status.data
        image = form.image.data

        # Create a new Property object and populate its attributes
        new_property = Property(name=name, size=size, bed=bed, price=price, bath=bath, location=location, category_id=category_id, status=status)

        # Set the user_id attribute to the currently logged-in user's ID
        new_property.user_id = current_user.id

        # Handle the uploaded image file
        if image:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_property.image = filename

        try:
            # Add the new property to the database
            db.session.add(new_property)
            db.session.commit()
            flash('Property added successfully!', 'success')
            return redirect(url_for('index'))
        except:
            db.session.rollback()
            flash('Error adding property. Please try again.', 'error')
            return redirect(url_for('index'))
        finally:
            db.session.close()

    categories = Category.query.all()
    form.category_id.choices = [(category.id, category.name) for category in categories]

    # If the request method is GET or form validation fails, display the form
    return render_template('add_property.html', form=form, categories=categories, property=property)


@app.route('/properties/<int:property_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def edit_property(property_id):
    form = PropertyForm()
    categories = Category.query.all()
    form.category_id.choices = [(category.id, category.name) for category in categories]

    property = Property.query.get(property_id)

    if not property:
        flash('Property not found.', 'error')
        return redirect(url_for('index'))

    if form.validate_on_submit():
        name = form.name.data
        size = form.size.data
        bed = form.bed.data
        price = form.price.data
        bath = form.bath.data
        location = form.address.data
        category_id = form.category_id.data
        status = form.status.data
        image = form.image.data

        # Update the property attributes
        property.name = name
        property.size = size
        property.bed = bed
        property.price = price
        property.bath = bath
        property.location = location
        property.category_id = category_id
        property.status = status

        # Handle the uploaded image file
        if image:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            property.image = filename

        try:
            # Commit the changes to the database
            db.session.commit()
            flash('Property updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating property. Please try again.', 'error')
            flash(f"Error: {str(e)}")
            return redirect(url_for('index'))

    # Populate form fields with existing property data
    form.name.data = property.name
    form.size.data = property.size
    form.bed.data = property.bed
    form.price.data = property.price
    form.bath.data = property.bath
    form.address.data = property.location
    form.category_id.data = property.category_id
    form.status.data = property.status

    return render_template('edit-property.html', form=form, categories=categories, property=property)



# Edit property

@app.route('/properties/<int:id>', methods=['POST'])
@login_required
@roles_required('admin')
def update_property(id):
    # Retrieve the property from the database
    property = Property.query.get_or_404(id)

    # Update the property attributes with the form data
    property.name = request.form.get("name")
    property.size = request.form.get("size")
    property.bed = request.form.get("bed")
    property.price = request.form.get("price")
    property.bath = request.form.get("bath")
    property.address = request.form.get("address")
    property.category_id = request.form.get("category_id")
    property.status = request.form.get("status")
    image = request.files.get("file-input")

    # Handle the updated image file
    if image:
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        property.image = filename

    try:
        # Commit the changes to the database
        db.session.commit()
        flash('Property updated successfully!', 'success')
    except:
        db.session.rollback()
        flash('Error updating property. Please try again.', 'error')
    finally:
        db.session.close()

    # Redirect to the admin homepage
    return redirect(url_for('admin_index'))



# Delete property
@app.route('/properties/<int:id>', methods=['DELETE'])
def delete_property(id):
    property = Property.query.get_or_404(id)
    db.session.delete(property)
    db.session.commit()
    return jsonify({'message': 'Property deleted successfully.'})


# Read properties
@app.route('/properties', methods=['GET'])
def get_properties():
    properties = Property.query.all()
    result = []
    for property in properties:
        property_data = {}
        property_data['id'] = property.id
        property_data['name'] = property.name
        property_data['image'] = property.image
        property_data['category_id'] = property.category_id
        property_data['status'] = property.status
        property_data['price'] = property.price
        property_data['size'] = property.size
        property_data['bed'] = property.bed
        property_data['bath'] = property.bath
        property_data['user_id'] = property.user_id
        property_data['location'] = property.location
        result.append(property_data)
    return jsonify(result)



# Endpoint to add a new agent
@app.route('/agents/register', methods=['GET', 'POST'])
def add_agent():
    if request.method == 'POST':
        # Process the form data
        fullname = request.form.get('fullname')
        designation = request.form.get('designation')
        twitter_handle = request.form.get('twitter_handle')
        instagram_handle = request.form.get('instagram_handle')
        facebook_handle = request.form.get('facebook_handle')
        image = request.files.get('image')  # Assuming the file input field name is 'image'
        
        # Perform server-side validation
        if not fullname or not designation or not image:
            flash('Please fill in all the required fields.', 'error')
            return redirect(url_for('add_agent'))
        
        filename = secure_filename(image.filename)
        # Save the uploaded image file
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Create a new agent object
        agent = Agent(
            fullname=fullname,
            designation=designation,
            twitter_handle=twitter_handle,
            instagram_handle=instagram_handle,
            facebook_handle=facebook_handle,
            image=filename
        )

        db.session.add(agent)
        db.session.commit()
        flash('Agent added successfully!', 'success')

        # Redirect to the appropriate page or render a success message
        return redirect(url_for('admin_agents'))

    # For GET requests, render the add_agent.html template
    return render_template('add_agent.html')


# Endpoint to retrieve all agents
@app.route('/admin/agents', methods=['GET'])
def get_agents():
    agents = Agent.query.all()
    return render_template('admin-agents.html', agents=agents)

# Endpoint to retrieve a specific agent
@app.route('/agents/<int:agent_id>', methods=['GET'])
def get_agent(agent_id):
    agent = Agent.query.get(agent_id)
    if agent is None:
        return jsonify({'message': 'Agent not found'})
    
    agent_data = {
        'id': agent.id,
        'fullname': agent.fullname,
        'designation': agent.designation,
        'twitter_handle': agent.twitter_handle,
        'instagram_handle': agent.instagram_handle,
        'facebook_handle': agent.facebook_handle,
        'image': agent.image
    }
    
    return jsonify(agent_data)

# Endpoint to update an agent
@app.route('/agents/<int:agent_id>', methods=['POST'])
def edit_agent(agent_id):
    agent = Agent.query.get(agent_id)
    if agent is None:
        return jsonify({'message': 'Agent not found'})

    data = request.form
    agent.fullname = data['fullname']
    agent.designation = data['designation']
    agent.twitter_handle = data['twitter_handle']
    agent.instagram_handle = data['instagram_handle']
    agent.facebook_handle = data['facebook_handle']
    # Handle the image update separately if required

    db.session.commit()

    return render_template('edit_agent.html', agent=agent, message='Agent updated successfully')

# Endpoint to delete an agent
@app.route('/agents/<int:agent_id>', methods=['DELETE'])
def delete_agent(agent_id):
    agent = Agent.query.get(agent_id)
    if agent is None:
        return jsonify({'message': 'Agent not found'})
    
    db.session.delete(agent)
    db.session.commit()

    return jsonify({'message': 'Agent deleted successfully'})


# Endpoint to render the admin page
@app.route('/admin')
def admin():
    return render_template('admin.html')

# ALTER TABLE properties ADD COLUMN location text;

# UPDATE properties SET location = '4, RealEstate Project road Dir' WHERE id = 4;
# UPDATE properties SET location = '56, John Wick st. Califonia, US' WHERE id = 5;
# UPDATE properties SET location = '8, Fred st. Bahamas, Caribbean' WHERE id = 6;
# UPDATE properties SET location = '45, Sunshine st. Manhattan Beach' WHERE id = 7;
# UPDATE properties SET location = '77, Apollo st. Asprovalta, Greece' WHERE id = 8;

#-----------------------------------------------------------------------------------------------
# Admin Files
#-----------------------------------------------------------------------------------------------
@app.route('/admin/agent')
def admin_agents():
    return render_template('admin-agents.html')

@app.route('/admin/categories')
def admin_categories():
    return render_template('admin-categories.html')

@app.route('/admin/index')
def admin_index():
    properties = Property.query.all()
    return render_template('admin.html', properties=properties)

@app.route('/admin/login')
def admin_login():
    return render_template('admin-login.html')

@app.route('/admin/properties')
def admin_properties():
    properties = Property.query.all()
    result = []
    for property in properties:
        property_data = {}
        property_data['id'] = property.id
        property_data['name'] = property.name
        property_data['image'] = property.image
        property_data['category_id'] = property.category_id
        property_data['status'] = property.status
        property_data['price'] = property.price
        property_data['size'] = property.size
        property_data['bed'] = property.bed
        property_data['bath'] = property.bath
        property_data['location'] = property.location
        result.append(property_data)
    return render_template('admin-properties.html', properties=properties)

@app.route('/admin/register')
def admin_register():
    return render_template('admin-register.html')


@app.route('/admin/users', methods=['GET'])
def admin_users():
    users = User.query.all()
    result = []
    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['role'] = user.role_id
        result.append(user_data)
    return render_template('admin-users.html', results=result)

@app.route('/admin/users/delete/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        # Optionally, you can return a success message or redirect to the user list
        flash(f"User: {user_id} has been removed!")
        return redirect('/admin/users')
    else:
        # Handle the case where the user with the given ID is not found
        flash("User not found")
        return redirect('/admin/users')
    
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found")
        return redirect('/admin/users')

    if request.method == 'POST':
        # Update user data based on the submitted form
        user.username = request.form['username']
        user.email = request.form['email']
        user.password = request.form['password']
        user.role_id = request.form['role_id']
        db.session.commit()
        flash(f"User: {user_id} has been Updated!")
        return redirect('/admin/users')

    # Render the edit user form
    return render_template('edit-user.html', user=user)

@app.route('/admin/charts-chartjs')
def admin_charts_chartjs():
    return render_template('charts-chartjs.html')

@app.route('/admin/charts-flot')
def admin_charts_flot():
    return render_template('charts-flot.html')

@app.route('/admin/charts-peity')
def admin_charts_peity():
    return render_template('charts-peity.html')

@app.route('/admin/font-fontawesome')
def admin_font_fontawesome():
    return render_template('font-fontawesome.html')

@app.route('/admin/font-themify')
def admin_font_themify():
    return render_template('font-themify.html')

@app.route('/admin/forgot-password')
def admin_forgot_password():
    return render_template('forgot-password.html')

@app.route('/admin/forms-advanced')
def admin_forms_advanced():
    return render_template('forms-advanced.html')

@app.route('/admin/forms-basic')
def admin_forms_basic():
    return render_template('forms-basic.html')

@app.route('/admin/maps-gmap')
def admin_maps_gmap():
    return render_template('maps-gmap.html')

@app.route('/admin/maps-vector')
def admin_maps_vector():
    return render_template('maps-vector.html')

@app.route('/admin/page-login')
def admin_page_login():
    return render_template('page-login.html')

@app.route('/admin/page-register')
def admin_page_register():
    return render_template('page-register.html')

@app.route('/admin/tables-basic')
def admin_tables_basic():
    return render_template('tables-basic.html')

@app.route('/admin/tables-data')
def admin_tables_data():
    return render_template('tables-data.html')

@app.route('/admin/ui-alerts')
def admin_ui_alerts():
    return render_template('ui-alerts.html')

@app.route('/admin/ui-badges')
def admin_ui_badges():
    return render_template('ui-badges.html')

@app.route('/admin/ui-buttons')
def admin_ui_buttons():
    return render_template('ui-buttons.html')

@app.route('/admin/ui-cards')
def admin_ui_cards():
    return render_template('ui-cards.html')

@app.route('/admin/ui-grids')
def admin_ui_grids():
    return render_template('ui-grids.html')

@app.route('/admin/ui-modals')
def admin_ui_modals():
    return render_template('ui-modals.html')

@app.route('/admin/ui-progressbar')
def admin_ui_progressbar():
    return render_template('ui-progressbar.html')

@app.route('/admin/ui-switches')
def admin_ui_switches():
    return render_template('ui-switches.html')

@app.route('/admin/ui-tabs')
def admin_ui_tabs():
    return render_template('ui-tabs.html')

@app.route('/admin/ui-typgraphy')
def admin_ui_typgraphy():
    return render_template('ui-typgraphy.html')

@app.route('/admin/widgets')
def admin_widgets():
    return render_template('widgets.html')

@app.route('/admin/pages-forget')
def admin_pages_forget():
    return render_template('pages-forget.html')





def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == "__main__":
    app.debug = True
    app.run()