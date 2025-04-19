from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
from io import StringIO
import os
import json
import time
from threading import Timer
import mysql.connector
from mysql.connector import Error
from authlib.integrations.flask_client import OAuth

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
import secrets

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import mysql.connector
from mysql.connector import Error
from google.cloud.sql.connector import Connector
import sqlalchemy

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per second", "50 per minute"],
)
# Explicitly set the path to your service account key
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = r'./t4-backend-469434088c8d.json'
def load_credentials():
    try:
        credentials, project = google.auth.default()
        return credentials
    except Exception as e:
        print(f"Error loading credentials: {e}")
        return None
    

# Configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# OAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),  # Set in environment variables
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),  # Set in environment variables
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    token_url='https://accounts.google.com/o/oauth2/token',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    redirect_uri="https://flask-app-250624862173.us-central1.run.app/callback"  # Update this to your deployed app's URL
)



# Initialize the Connector object
connector = Connector()
# function to return the database connection object
def getconn():
    conn = connector.connect(
        instance_connection_string=os.getenv('INSTANCE_CONNECTION_STRING'),  # e.g. "project:region:instance"
        driver="pymysql",
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASS'),
        db=os.getenv('DB_NAME')
    )
    return conn

# Database connection
def get_db_connection():
    try:
        # Create SQLAlchemy connection pool
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=getconn,
        )
        
        # Get a connection from the pool and return it
        connection = pool.connect()
        return connection
    except Exception as e:
        print(f"Error connecting to Cloud SQL: {e}")
        return None
    
""" # Helper function for executing SQL queries
def execute_query(query, params=()):
    connection = get_db_connection()
    if connection is None:
        return []
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        results = cursor.fetchall()
        return results
    except Error as e:
        #print(f"Error executing query: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close() """
@app.route("/test-database", methods=["GET"])
def test_database_connection():
    connection = get_db_connection()
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    
    try:
        # Use SQLAlchemy's text method to create a SQL statement
        query = sqlalchemy.text("SELECT * FROM User LIMIT 5")
        
        # Execute the query
        result = connection.execute(query)
        
        # Fetch all results
        results = result.fetchall()
        
        # Convert results to a list of dictionaries
        # Use column names from the result
        columns = result.keys()
        user_list = [dict(zip(columns, row)) for row in results]
        
        return jsonify({
            "message": "Database connection successful",
            "users": user_list,
            "user_count": len(user_list)
        }), 200
    
    except Exception as e:
        return jsonify({
            "message": "Error querying database",
            "error": str(e)
        }), 500
    
    finally:
        # Close the connection if it's still open
        if connection:
            connection.close()

def call_procedure(procedure_name, params=()):
    connection = get_db_connection()
    if connection is None:
        return []
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.callproc(procedure_name, params)
        
        # Get results from all result sets
        results = []
        for result in cursor.stored_results():
            results.extend(result.fetchall())
            
        connection.commit()
        return results
    except Error as e:
        print(f"Error calling procedure {procedure_name}: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Decorator to protect routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ["PUT", "POST"] and "user" not in session:
            return jsonify({"message": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route("/events", defaults={"event_id": None}, methods=["GET", "POST"])
@app.route("/events/<int:event_id>", methods=["GET", "PUT", "DELETE"])
@login_required
def events(event_id = None):
    connection = get_db_connection()  # Establish a database connection
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    cursor = connection.cursor(dictionary=True)
        
    if request.method == 'GET':
        if event_id is None:
            #print("return full db")
            
            try:
                rows = cursor.callproc("getAllUpcommingEvents")
                cursor.close()
                connection.close()
                return jsonify({"message": rows}), 200
            except:
                cursor.close()
                connection.close()
                return jsonify({"message": "error calling all events"}), 401
                
        
        #print(f"Fetching event with id: {event_id}")
        try:
            row = cursor.callproc("eventDetailByID")
            cursor.close()
            connection.close()
            return jsonify({"message": row}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "error fetching event"}), 401 

    elif request.method == 'POST':
        #print("create event")
        data = request.get_json()
        if not data:
            cursor.close()
            connection.close()
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        try: 
            title = data["title"]
            description = data["description"]
            eventDate = data["eventDate"]
            location = data["location"]
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "Missing data"}), 400
        
        cursor.callproc("createEvent",(title, description, eventDate, location,))

        cursor.close()
        connection.close()
        return jsonify({"message": "Created event"}), 201
        
    elif request.method == 'PUT':
        #print(f"editing event with id: {event_id}")
    
        data = request.get_json()
        if not data:
            cursor.close()
            connection.close()
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        try:
            title = data["title"]
            description = data["description"]
            eventDate = data["eventDate"]
            location = data["location"]
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "Missing data"}), 400
        
        try:
            cursor.callproc("updateEvent",(event_id, title, description, eventDate, location,))
            cursor.close()
            connection.close()
            return jsonify({"message": "Updated event"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "error updating event"}), 401
        
    elif request.method == 'DELETE':
        #print(f"deleting event with id: {event_id}")
        try:
            cursor.callproc("deleteEvent",(event_id,))
            cursor.close()
            connection.close()
            return jsonify({"message": "deleted event"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "event cannot be deleted"}), 401
    

@app.route("/events/<int:event_id>/register", methods=["POST"])
@login_required
def register_user(event_id):
    #print(f"user is being added to event with ID: {event_id}")
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
    
    connection = get_db_connection()  # Establish a database connection
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    cursor = connection.cursor(dictionary=True)
    
    try:
        cursor.callproc("newManager", (event_id, data["id"],))
        cursor.close()
        connection.close()
        return jsonify({"message": "added manager"}), 200
    except:
        cursor.close()
        connection.close()
        return jsonify({"message": "could not add manager"}), 400  
    
@app.route("/events/<int:event_id>/registrations", defaults={"registration_id": None}, methods =["GET"])
@app.route("/events/<int:event_id>/registrations/<int:registration_id>", methods =["PUT", "DELETE"])
@login_required
def registrations(event_id, registration_id = None):
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
    if request.method == "GET":
        #print(f"returning all users that have registered for event with id: {event_id}")
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(dictionary=True)
        
        try:
            rows = cursor.callproc("allEventsByAdmin", (data["id"]))
            cursor.close()
            connection.close()
            return jsonify({"message": rows})
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to get info"}), 400
            
        
    if request.method == "PUT":
        if registration_id is None:
            return jsonify({"message": "no registration id provided"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.callproc("updateRegistration", registration_id, data["id"] , event_id,)
            cursor.close()
            connection.close()
            return jsonify({"message": "updated registration"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to update registration"}), 400
    
    if request.method == "DELETE":
        if registration_id is None:
            return jsonify({"message": "no registration id provided"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.callproc("deleteManagerFromEvent", data["id"], event_id,)
            cursor.close()
            connection.close()
            return jsonify({"message": "deleted manager"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to delete manager"}), 400
            
        #print(f"deleted user from event {event_id} register id: {registration_id}")
    
@app.route("/users", defaults={"id": None}, methods= ["GET", "POST"])
@app.route("/users/<int:id>", methods= ["GET", "PUT", "DELETE"])
@login_required
def users(id = None):
    if request.method == "GET":
        if id is None:
            connection = get_db_connection()  # Establish a database connection
            if connection is None:
                return jsonify({"message": "Database connection failed"}), 500
            cursor = connection.cursor(dictionary=True)
            
            try:
                rows = cursor.callproc("getAllUsers",)
                cursor.close()
                connection.close()
                return jsonify({"message": rows}), 200
            except:
                cursor.close()
                connection.close()
                return jsonify({"message": "unable to get all users"}), 400
        
        
        #if userid is given
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(dictionary=True)
        
        try:
            row = cursor.callproc("getUserByID", id,)
            cursor.close()
            connection.close()
            return jsonify({"message": row}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": f"unable to get data on id {id}"}), 400
    
    if request.method == "POST":
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.callproc("assignMultipleManagers", id, data["ids"],)
            cursor.close()
            connection.close()
            return jsonify({"message": "added new manager(s)"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to add manager(s)"}), 400
    
    if request.method == "PUT":
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.callproc("updateUserInfo", id, data["first_name"], data["last_name"], data["email"])
            cursor.close()
            connection.close()
            return jsonify({"message": "user info updated"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to update user info"}), 400
    

    if request.method == "DELETE":
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.callproc("removeMultipleManagers", id, data["ids"], )
            cursor.close()
            connection.close()
            return jsonify({"message": "deleted managers"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to delete managers"}), 400
    
if __name__ == '__main__':
    app.run(port=5000, debug=True)


    # User class for session management
class User:
    def __init__(self, user_id, email, name):
        self.id = user_id
        self.email = email
        self.name = name
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return str(self.id)

# Helper to load user from session or database
def load_user(user_id):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, email, name FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        connection.close()
        if user_data:
            return User(user_data['id'], user_data['email'], user_data['name'])
    return None

# OAuth 2.0 Login Route
@app.route("/login", methods=["GET"])
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

# OAuth 2.0 Authorization Callback
@app.route("/authorize")
def authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    
    email = user_info['email']
    name = user_info['name']
    
    # Check if user exists, or create a new one
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, email, name FROM users WHERE email = %s", (email,))
        user_data = cursor.fetchone()
        
        if not user_data:
            # Register new user
            cursor.execute(
                "INSERT INTO users (email, name) VALUES (%s, %s)",
                (email, name)
            )
            connection.commit()
            cursor.execute("SELECT id, email, name FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()
        
        user = User(user_data['id'], user_data['email'], user_data['name'])
        session['user_id'] = user.id  # Store user ID in session
        cursor.close()
        connection.close()
        
        return redirect(url_for('protected'))
    
    return jsonify({"message": "Authentication failed"}), 401

# Logout Route
@app.route("/logout", methods=["POST"])
def logout():
    session.pop('user_id', None)
    return jsonify({"message": "Logged out"}), 200

# Setup to register a none logged in user to an event
@app.route("/register", methods=["POST"])
def register():
    return jsonify({"message": "Registration handled via OAuth. Use /login instead."}), 200

# Protected Route Example
@app.route("/protected", methods=["GET"])
def protected():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401
    user = load_user(user_id)
    if user:
        return jsonify({"message": f"Welcome, {user.name}!"}), 200
    return jsonify({"message": "User not found"}), 404