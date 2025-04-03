from flask import Flask, request, jsonify, send_file, session, request, url_for, redirect
from flask_cors import CORS
from io import StringIO
from functools import wraps
import os
import json
from threading import Timer
import mysql.connector
from mysql.connector import Error
import datetime
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

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
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = r'./t4-backend-ce84965061ed.json'
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


app.config["GOOGLE_CLIENT_ID"] = os.getenv("GOOGLE_CLIENT_ID")
app.config["GOOGLE_CLIENT_SECRET"] = os.getenv("GOOGLE_CLIENT_SECRET")

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={"scope": "openid email profile"},
    api_base_url="https://www.googleapis.com/oauth2/v1/",
)





# Initialize the Connector object
connector = Connector()
# function to return the database connection object
def getconn():
    conn = connector.connect(
        instance_connection_string=os.getenv('INSTANCE_CONNECTION_STRING'),  
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

            
            

@app.route("/events", defaults={"event_id": None}, methods=["GET", "POST"])
@app.route("/events/<int:event_id>", methods=["GET", "PUT", "DELETE"])
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
    

@app.route("/")
def home():
    user = session.get("user")
    print(user)
    return f"Hello, {user['name']}!" if user else "Hello, Guest! <a href='/login'>Login with Google</a>"

@app.route("/login")
def login():
    return google.authorize_redirect(url_for("callback", _external=True))

@app.route("/login-failed")
def failed_login():
    return f"Login Failed"


@app.route("/callback")
def callback():
    token = google.authorize_access_token()
    user = google.get("userinfo").json()  


    user_email = user.get("email")
    if not user_email:
        session.pop("user", None)
        return redirect(url_for("failed_login") + "?error=Email not provided by Google")

    print(user_email)
    allowed_domain = "gmail.com"  
    if not (user_email == "sales.club@westernusc.ca" or "westernsalesclub@gmail.com"):
        session.pop("user", None)
        return redirect(url_for("failed_login") + "?error=Only users from " + allowed_domain + " are allowed to sign in")

    # if we want to allow people form the DB
    # connection = get_db_connection()
    # if connection is None:
    #     session.pop("user", None)
    #     return redirect(url_for("home") + "?error=Database connection failed")

    try:

        # query = sqlalchemy.text("SELECT * FROM User WHERE email = :email")
        # result = connection.execute(query, {"email": user_email})
        # user_record = result.fetchone()

        # if not user_record:
        #     session.pop("user", None)
        #     return redirect(url_for("home") + "?error=User not found in the database")

        session["user"] = user
        return redirect(url_for("home"))

    except Exception as e:
        session.pop("user", None)
        return redirect(url_for("failed_login") + "?error=Error checking user: " + str(e))

    # finally:
        # if connection:
        #     connection.close()

# Route: Logout
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))


if __name__ == '__main__':
    app.run(port=5000, debug=True)

