from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
from io import StringIO
import os
import json
import time
from threading import Timer
import mysql.connector
from mysql.connector import Error

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
import secrets

app = Flask(__name__)
CORS(app)

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
    redirect_uri='http://localhost:5000/authorize/google'  # Adjust for production
)

# Database connection
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD')
        )
        if connection.is_connected():
            return connection
    except Error as e:
        #print(f"Error connecting to MySQL database: {e}")
        return None

# Helper function for executing SQL queries
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
            connection.close()
            
            

@app.route("/events", defaults={"event_id": None}, methods=["GET", "POST"])
@app.route("/events/<int:event_id>", methods=["GET", "PUT", "DELETE"])
def events(event_id = None):
    if request.method == 'GET':
        if event_id is None:
            #print("return full db")
            
            try:
                rows = cursor.callproc("getAllUpcommingEvents")
                return jsonify({"message": rows}), 200
            except:
                return jsonify({"message": "error calling all events"}), 401
                
        
        #print(f"Fetching event with id: {event_id}")
        try:
            row = cursor.callproc("eventDetailByID")
            return jsonify({"message": row}), 200
        except:
            return jsonify({"message": "error fetching event"}), 401 

    elif request.method == 'POST':
        #print("create event")
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        title = data["title"]
        description = data["description"]
        eventDate = data["eventDate"]
        location = data["location"]
        
        cursor.callproc("createEvent",(title, description, eventDate, location,))

        return jsonify({"message": "Created event"}), 201
        
    elif request.method == 'PUT':
        #print(f"editing event with id: {event_id}")
        cursor.callproc("eventDetailByID")
        
        for result in cursor.stored_results():
            rows = result.fetchall()
            title = rows[0]
            description = rows[1]
            eventDate = rows[2]
            location = rows[3]
        
        try:
            cursor.callproc("updateEvent",(event_id, title, description, eventDate, location,))
            return jsonify({"message": "Updated event"}), 200
        except:
            return jsonify({"message": "error updating event"}), 401
        
    elif request.method == 'DELETE':
        #print(f"deleting event with id: {event_id}")
        return
    

@app.route("/events/<int:event_id>/register", methods=["POST"])
def register_user(event_id):
    #print(f"user is being added to event with ID: {event_id}")
    return 
    
@app.route("/events/<int:event_id>/registrations", defaults={"registration_id": None}, methods =["GET"])
@app.route("/events/<int:event_id>/registrations/<int:registration_id>", methods =["PUT", "DELETE"])

def registrations(event_id, registration_id = None):
    if request.method == "GET":
        #print(f"returning all users that have registered for event with id: {event_id}")
        return
    
    if request.method == "PUT":
        if registration_id is None:
            #print("provide a registration id")
            return
        #print(f"added user to event id: {event_id} register id: {registration_id}")
        return
    
    if request.method == "DELETE":
        if registration_id is None:
            #print("provide a registration id")
            return
        #print(f"deleted user from event {event_id} register id: {registration_id}")
    

@app.route("/login", methods = ["POST"])
def login():
    if request.method == "POST":
        #print("checking if user can log in")
        return

@app.route("/logout", methods = ["POST"])
def logout():
    if request.method == "POST":
        #print("logging out")
        return
    
@app.route("/register", methods = ["POST"])
def register():
    if request.method == "POST":
        #print("registering")
        return
    
    
@app.route("/users", defaults={"id": None}, methods= ["GET", "POST"])
@app.route("/users/<int:id>", methods= ["GET", "PUT", "DELETE"])
def users(id = None):
    if request.method == "GET":
        if id is None:
            #print("get all users")
            return
        #print(f"retrieving user with id: {id}")
        return
    
    if request.method == "POST":
        #print("adding new user")
        return
    
    if request.method == "PUT":
        #print(f"editing user with id: {id}")
        return
    
    if request.method == "DELETE":
        #print(f"deleting user with id: {id}")
        return
    
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