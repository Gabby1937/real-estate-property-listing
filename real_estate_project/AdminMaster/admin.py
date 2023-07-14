from flask import request, jsonify, render_template, redirect, Flask, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_migrate import Migrate
import psycopg2, os, requests
from models import Category, Property, User, Role, Agent
from database import db, migrate
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, LoginManager, login_user, logout_user, current_user
from flask_user import roles_required
from flask_wtf import FlaskForm


app = Flask(__name__)


ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}  # define allowed image file extensions
UPLOAD_FOLDER = './static/img'  # set your upload folder path

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://boss:key@localhost:5432/realestatedb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'mysecretkey'
db.init_app(app)
migrate = Migrate(app, db)
migrate.init_app(app, db)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # Load the user object from the database based on the user ID
    # Replace this with your actual logic to retrieve the user from the database
    user = User.query.get(int(user_id))
    return user

with app.app_context():
    db.create_all()



# def get_countries():
#     url = "https://restcountries.com/v3.1/all"  # API endpoint for retrieving all countries
#     response = requests.get(url)
#     if response.status_code == 200:
#         countries = response.json()
#         return countries
#     else:
#         return None

@app.route("/", methods=['GET', 'POST'])
def index():
    properties = Property.query.all()
    categories = Category.query.all()
    filtered_properties = properties  # Set the default value for filtered_properties
    
    #countries = get_countries()  # Retrieve the list of countries
    
    # if countries is not None:
    #     countries = sorted(countries, key=lambda c: c['name']['common'])
    # else:
    #     300
    
    if request.method == 'POST':
        keyword = request.form.get('keyword')
        property_type = request.form.get('property_type')
        location = request.form.get('location')

        if keyword:
            # Search by property name or location
            filtered_properties = [p for p in filtered_properties if keyword.lower() in p.name.lower() or keyword.lower() in p.location.lower()]

        if property_type and property_type != 'all':
            # Search by property type (category)
            filtered_properties = [p for p in filtered_properties if p.category_id == int(property_type)]

        if location and location != 'all':
            # Search by location
            filtered_properties = [p for p in filtered_properties if location.lower() in p.location.lower()]

    return render_template('index.html', properties=filtered_properties, categories=categories, category_icons=category_icons) #countries=countries)
    #return render_template('index.html', properties=filtered_properties, categories=categories, countries=countries)

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
    if request.method == "POST":
        # Retrieve the form data
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        # Debugging statement to check the form data
        print(f'Form data: username={username}, email={email}, password={password}')
        
        # Create a new User object and add it to the database
        new_user = User(username=username, email=email, password=password)
        
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
        
        # Redirect the user to the login page
        return redirect(url_for('login'))
    
    # If the request method is GET, display the form
    return render_template('./signup.html')



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Retrieve the form data
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Check if the user exists in the database
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Use Flask-Login's login_user function to log in the user
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        
        flash('Invalid username or password', 'error')
        
    return render_template('login.html')

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


@app.route("/add_property", methods=["GET", "POST"])
@login_required
@roles_required('admin')
def add_property():
    if request.method == "POST":
        # Retrieve the form data
        name = request.form.get("name")
        image = request.files.get("file-input")  # use request.files to retrieve uploaded file
        category_id = request.form.get("category_id")
        status = request.form.get("status")
        address = request.form.get("address")
        price = request.form.get("price")
        size = request.form.get("size")
        bed = request.form.get("bed")
        bath = request.form.get("bath")
        location = request.form.get("location")
        
        # Check if an image file was uploaded
        print(image)
        print(name)
        print(category_id)
        print(size)
        print(bed)
        print(bath)
        print(address)
        print(status)
        print(location)
        print(price)
        
        filename = secure_filename(image.filename)
        print(f"filename: {filename}")
        print(f"extension: {filename.rsplit('.', 1)[1].lower()}")
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Assign the current user's ID to the new property's user_id field
        user_id = current_user.id
        
        # Create a new Property object and add it to the database
        new_property = Property(
            name=name, 
            image=filename, 
            category_id=category_id, 
            status=status, 
            price=price, 
            size=size, 
            bed=bed, 
            bath=bath, 
            location=location,
            user_id=user_id
        )       
        try:
            db.session.add(new_property)
            db.session.commit()
            flash('Property added successfully!', 'success')
        except:
            db.session.rollback()
            flash('Error adding property. Please try again.', 'error')
        finally:
            db.session.close()
        
        # Redirect the user to the home page
        return redirect(url_for('index'))
    
    # If the request method is GET, display the form
    categories = Category.query.all()
    return render_template('./add_property.html', categories=categories)

# Edit property

@app.route('/properties/<int:id>', methods=['PUT'])
def update_property(id):
    property = Property.query.get_or_404(id)
    property.name = request.json['name']
    property.image = request.json['image']
    property.category_id = request.json['category_id']
    property.status = request.json['status']
    property.price = request.json['price']
    property.size = request.json['size']
    property.bed = request.json['bed']
    property.bath = request.json['bath']
    property.location = request.json['location']
    property.user_id = request.json['user_id']
    db.session.commit()
    return jsonify({'message': 'Property updated successfully.'})


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
@app.route('/agents', methods=['POST'])
def add_agent():
    # Check if the request method is GET
    if request.method == 'GET':
        # Render the add_agent.html template
        return render_template('add_agent.html')
    
    # If the request method is POST, process the form data
    data = request.get_json()
    fullname = data['fullname']
    designation = data['designation']
    twitter_handle = data['twitter_handle']
    instagram_handle = data['instagram_handle']
    facebook_handle = data['facebook_handle']
    image = data['image']

    agent = Agent(fullname=fullname, designation=designation, twitter_handle=twitter_handle,
                  instagram_handle=instagram_handle, facebook_handle=facebook_handle, image=image)
    
    db.session.add(agent)
    db.session.commit()
    flash('Agent Added Successfully!!')

    return jsonify({'message': 'Agent added successfully'})

# Endpoint to retrieve all agents
@app.route('/agents', methods=['GET'])
def get_agents():
    agents = Agent.query.all()
    result = []
    for agent in agents:
        agent_data = {
            'id': agent.id,
            'fullname': agent.fullname,
            'designation': agent.designation,
            'twitter_handle': agent.twitter_handle,
            'instagram_handle': agent.instagram_handle,
            'facebook_handle': agent.facebook_handle,
            'image': agent.image
        }
        result.append(agent_data)
    
    return jsonify(result)

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
@app.route('/agents/<int:agent_id>', methods=['PUT'])
def update_agent(agent_id):
    agent = Agent.query.get(agent_id)
    if agent is None:
        return jsonify({'message': 'Agent not found'})
    
    data = request.get_json()
    agent.fullname = data['fullname']
    agent.designation = data['designation']
    agent.twitter_handle = data['twitter_handle']
    agent.instagram_handle = data['instagram_handle']
    agent.facebook_handle = data['facebook_handle']
    agent.image = data['image']
    
    db.session.commit()

    return jsonify({'message': 'Agent updated successfully'})

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == "__main__":
    app.debug = True
    app.run()