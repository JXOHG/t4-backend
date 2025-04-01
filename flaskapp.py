from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from io import StringIO
from functools import wraps
import os
import json
from threading import Timer
import mysql.connector
from mysql.connector import Error
import bcrypt
import jwt
import datetime



app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('ENCRYPTION_KEY', 'default_secret_key')  
# Store blacklisted tokens
blacklisted_tokens = set()


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
    


# JWT token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
            
        if token.startswith('Bearer '):
            token = token.replace('Bearer ', '')
            
        # Check if token is blacklisted
        if token in blacklisted_tokens:
            return jsonify({"message": "Token has been blacklisted"}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    return decorated


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"message": "Invalid JSON or missing username/password"}), 400
    
    username = data["username"]
    password = data["password"]
    
    try:
        query = "SELECT id, username, secret_key FROM users WHERE username = %s"
        results = execute_query(query, (username,))
        
        if not results:
            return jsonify({'error': 'Invalid credentials'}), 401
            
        stored_password = results[0]["secret_key"]
        
        # Check if password matches (assuming stored_password is already hashed)
        if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            # Generate JWT token
            token = jwt.encode({
                'username': username,
                'user_id': results[0]["id"],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({'token': token, 'username': username}), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({"message": "Error during login", "error": str(e)}), 500

@app.route('/api/protected', methods=['GET'])
@token_required
def protected():
    token = request.headers.get('Authorization').replace('Bearer ', '')
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    return jsonify({
        'message': f"Welcome, {data['username']}!", 
        'user': data['username']
    }), 200

@app.route("/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Missing token"}), 400
    
    if token.startswith('Bearer '):
        token = token.replace('Bearer ', '')
    
    try:
        # Verify token is valid before blacklisting
        jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Add token to blacklist
        blacklisted_tokens.add(token)
        
        return jsonify({"message": "Logout successful"}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token already expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
    
    # Validate required fields
    required_fields = ["username", "password", "email"]
    for field in required_fields:
        if field not in data:
            return jsonify({"message": f"Missing required field: {field}"}), 400
    
    username = data["username"]
    password = data["password"]
    email = data["email"]
    
    # Check if username already exists
    user_check = execute_query("SELECT id FROM users WHERE username = %s", (username,))
    if user_check:
        return jsonify({"message": "Username already exists"}), 400
    
    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    try:
        # Insert new user
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO users (username, secret_key, email) VALUES (%s, %s, %s)",
            (username, hashed_password, email)
        )
        connection.commit()
        user_id = cursor.lastrowid
        cursor.close()
        connection.close()
        
        return jsonify({
            "message": "User registered successfully",
            "user_id": user_id
        }), 201
    except Exception as e:
        return jsonify({"message": f"Error registering user: {str(e)}"}), 500
    
    
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