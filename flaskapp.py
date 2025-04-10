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
#import sqlalchemy
import pymysql
from google.cloud import storage
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per second", "50 per minute"],
)
# Explicitly set the path to your service account key
#os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = r'./t4-backend-ce84965061ed.json'

#kenneth
#os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = r't4-backend-4e28b71354cb.json'
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
        """ # Create SQLAlchemy connection pool
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=getconn,
        )
        
        # Get a connection from the pool and return it
        connection = pool.connect()  """
        
        
        return getconn()
        #return connection
    except Exception as e:
        print(f"Error connecting to Cloud SQL: {e}")
        return None
    
""" # Helper function for executing SQL queries
def execute_query(query, params=()):
    connection = get_db_connection()
    if connection is None:
        return []
    
    try:
        cursor = connection.cursor(pymysql.cursors.DictCursor)
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
""" @app.route("/test-database", methods=["GET"])
def test_database_connection():
    connection = get_db_connection()
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    
    try:
        # Use SQLAlchemy's text method to create a SQL statement
        #query = sqlalchemy.text("SELECT * FROM User LIMIT 5")
        #query = sqlalchemy.text("SELECT * FROM Event")
        #query = sqlalchemy.text("CALL createEvent('test', 'test event', '2025-07-15 00:00:00', 'test location')")
        query = sqlalchemy.text("SHOW CREATE PROCEDURE UpdateUser")

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
            """

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
    cursor = connection.cursor(pymysql.cursors.DictCursor)
        
    if request.method == 'GET':
        if event_id is None:
            #print("return full db")
            
            try:
                cursor.callproc("GetUpcomingEvents")
                rows = cursor.fetchall()
                cursor.close()
                connection.close()
                return jsonify({"message": rows}), 200
            except Exception as e:
                cursor.close()
                connection.close()
                return jsonify({"message": f"error calling all events: {str(e)}"}), 401
                
        
        #print(f"Fetching event with id: {event_id}")
        try:
            cursor.callproc("GetEventDetails", (event_id,) )
            row = cursor.fetchall()
            cursor.close()
            connection.close()
            return jsonify({"message": row}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"error fetching event: {str(e)}"}), 401 

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
        
        try:
            # Example input: 'Mon, 15 Jul 2025 00:00:00 GMT'
            parsed_event_date = datetime.strptime(eventDate, "%a, %d %b %Y %H:%M:%S GMT")
            formatted_event_date = parsed_event_date.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            cursor.close()
            connection.close()
            return jsonify({"message": "Invalid date format"}), 400
        
        cursor.callproc("createEvent",(title, description, formatted_event_date, location,))
        connection.commit()

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
            # Example input: 'Mon, 15 Jul 2025 00:00:00 GMT'
            parsed_event_date = datetime.strptime(eventDate, "%a, %d %b %Y %H:%M:%S GMT")
            formatted_event_date = parsed_event_date.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            cursor.close()
            connection.close()
            return jsonify({"message": "Invalid date format"}), 400
        
        try:
            cursor.callproc("UpdateEvent",(event_id, title, description, formatted_event_date, location,))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({"message": "Updated event"}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"error updating event: {str(e)}"}), 401 
        
    elif request.method == 'DELETE':
        #print(f"deleting event with id: {event_id}")
        try:
            cursor.callproc("DeleteEvent",(event_id,))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({"message": f"deleted event {event_id}"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "event cannot be deleted"}), 401
    
""" 
@app.route("/events/<int:event_id>/register", methods=["POST"])
def register_user(event_id):
    #print(f"user is being added to event with ID: {event_id}")
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
    
    connection = get_db_connection()  # Establish a database connection
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    
    try:
        cursor.callproc("AssignManager", (data["id"], event_id,))
        cursor.close()
        connection.close()
        return jsonify({"message": "added manager"}), 200
    except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"could not add manager: {str(e)}"}), 401  

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
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        
        try:
            cursor.callproc("GetManagedEvents", (data["id"],))
            rows = cursor.fetchall()
            cursor.close()
            connection.close()
            return jsonify({"message": rows})
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"unable to get info: {str(e)}"}), 401  
            
        
    if request.method == "PUT":
        if registration_id is None:
            return jsonify({"message": "no registration id provided"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        
        try:
            cursor.callproc("updateRegistration", (registration_id, data["id"] , event_id,))
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
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        
        try:
            cursor.callproc("deleteManagerFromEvent", data["id"], event_id,)
            cursor.close()
            connection.close()
            return jsonify({"message": "deleted manager"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to delete manager"}), 400
            
        #print(f"deleted user from event {event_id} register id: {registration_id}") """

@app.route("/users", defaults={"id": None}, methods= ["GET"])
@app.route("/users/<int:id>", methods= ["GET", "PUT"])
def users(id = None):
    if request.method == "GET":
        if id is None:
            connection = get_db_connection()  # Establish a database connection
            if connection is None:
                return jsonify({"message": "Database connection failed"}), 500
            cursor = connection.cursor(pymysql.cursors.DictCursor)
            
            try:
                cursor.callproc("GetAllUsers",)
                rows = cursor.fetchall()
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
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        
        try:
            cursor.callproc("GetUserByID", (id,))
            row = cursor.fetchall()
            cursor.close()
            connection.close()
            return jsonify({"message": row}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": f"unable to get data on id {id}"}), 400
        
    if request.method == "PUT":
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        
        try:
            cursor.callproc("UpdateUser", (id, data["first_name"], data["last_name"], data["email"],))
            connection.commit() 
            cursor.close()
            connection.close()
            return jsonify({"message": "user info updated"}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"unable to update user info: {str(e)}"}), 401 
    
"""     if request.method == "POST":
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        
        try:
            cursor.callproc("AssignMultipleManagers", id, data["ids"],)
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({"message": "added new manager(s)"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to add manager(s)"}), 400 """

"""     if request.method == "DELETE":
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        
        connection = get_db_connection()  # Establish a database connection
        if connection is None:
            return jsonify({"message": "Database connection failed"}), 500
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        
        try:
            cursor.callproc("RemoveMultipleManagers", id, data["ids"], )
            cursor.close()
            connection.close()
            return jsonify({"message": "deleted managers"}), 200
        except:
            cursor.close()
            connection.close()
            return jsonify({"message": "unable to delete managers"}), 400"""
    
if __name__ == '__main__':
    #app.run(port=5000, debug=True)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
    #app.run(host='0.0.0.0', port=8080)


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


#Google Cloud storage helper
# Add this helper function to handle Google Cloud Storage operations
def get_storage_client():
    """Returns a Google Cloud Storage client."""
    return storage.Client()


def upload_file_to_gcs(file, bucket_name="t4-backend", folder="event_images"):
    """
    Uploads a file to Google Cloud Storage bucket
    
    Args:
        file: The file object to upload
        bucket_name: Name of the GCS bucket
        folder: Folder name within the bucket
        
    Returns:
        Public URL of the uploaded file or None if upload fails
    """
    try:
        # Generate a secure filename with a UUID to prevent name collisions
        original_filename = secure_filename(file.filename)
        filename_parts = original_filename.rsplit('.', 1)
        
        if len(filename_parts) > 1:
            ext = filename_parts[1].lower()
            unique_filename = f"{uuid.uuid4().hex}.{ext}"
        else:
            unique_filename = f"{uuid.uuid4().hex}"
            
        # Path in the bucket where the file will be stored
        destination_blob_name = f"{folder}/{unique_filename}"
        
        # Get the storage client and bucket
        storage_client = get_storage_client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)
        
        # Upload the file
        blob.upload_from_file(file, content_type=file.content_type)
        
        # Make the blob publicly accessible
        blob.make_public()
        
        # Return the public URL
        return blob.public_url
    
    except Exception as e:
        print(f"Error uploading file to GCS: {e}")
        return None
    
def delete_file_from_gcs(file_url, bucket_name="t4-backend"):
    """
    Deletes a file from Google Cloud Storage based on the URL
    
    Args:
        file_url: Public URL of the file to delete
        bucket_name: Name of the GCS bucket
        
    Returns:
        Boolean indicating success or failure
    """
    try:
        # Extract the blob name from the URL
        # URL format: https://storage.googleapis.com/BUCKET_NAME/BLOB_NAME
        blob_name = file_url.split(f"https://storage.googleapis.com/{bucket_name}/")[1]
        
        # Get the storage client and bucket
        storage_client = get_storage_client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        # Delete the blob
        blob.delete()
        return True
    
    except Exception as e:
        print(f"Error deleting file from GCS: {e}")
        return False


#endpoint for image handling
@app.route("/events/<int:event_id>/image", methods=["POST", "GET", "DELETE"])
def handle_event_image(event_id):
    # Check if event exists
    connection = get_db_connection()
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Verify the event exists
        query = sqlalchemy.text("SELECT event_id FROM Event WHERE event_id = :event_id")
        result = connection.execute(query, {"event_id": event_id})
        event = result.fetchone()
        
        if not event:
            cursor.close()
            connection.close()
            return jsonify({"message": f"Event with ID {event_id} not found"}), 404
        
        # Handle image upload
        if request.method == "POST":
            # Check if file is in the request
            if 'image' not in request.files:
                cursor.close()
                connection.close()
                return jsonify({"message": "No image file provided"}), 400
            
            file = request.files['image']
            
            # Check if file has a name
            if file.filename == '':
                cursor.close()
                connection.close()
                return jsonify({"message": "No selected file"}), 400
            
            # Check file extension
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
            if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                cursor.close()
                connection.close()
                return jsonify({"message": "Invalid file type. Allowed types: png, jpg, jpeg, gif, webp"}), 400
            
            # Upload to GCS
            file_url = upload_file_to_gcs(file)
            if not file_url:
                cursor.close()
                connection.close()
                return jsonify({"message": "Failed to upload image"}), 500
            
            # Check if there's already an image for this event
            query = sqlalchemy.text("SELECT detail_id, image_url FROM Event_Detail WHERE event_id = :event_id")
            result = connection.execute(query, {"event_id": event_id})
            existing_detail = result.fetchone()
            
            if existing_detail:
                # Update existing record
                old_image_url = existing_detail.image_url
                
                # Delete old image if it exists
                if old_image_url:
                    delete_file_from_gcs(old_image_url)
                
                # Update record
                update_query = sqlalchemy.text(
                    "UPDATE Event_Detail SET image_url = :image_url, updated_at = CURRENT_TIMESTAMP WHERE detail_id = :detail_id"
                )
                connection.execute(update_query, {
                    "image_url": file_url,
                    "detail_id": existing_detail.detail_id
                })
            else:
                # Create new record
                insert_query = sqlalchemy.text(
                    "INSERT INTO Event_Detail (event_id, image_url) VALUES (:event_id, :image_url)"
                )
                connection.execute(insert_query, {
                    "event_id": event_id,
                    "image_url": file_url
                })
            
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({
                "message": "Image uploaded successfully",
                "image_url": file_url
            }), 201
        
        # Handle image retrieval
        elif request.method == "GET":
            query = sqlalchemy.text("SELECT image_url FROM Event_Detail WHERE event_id = :event_id")
            result = connection.execute(query, {"event_id": event_id})
            detail = result.fetchone()
            
            cursor.close()
            connection.close()
            
            if not detail or not detail.image_url:
                return jsonify({"message": "No image found for this event"}), 404
            
            return jsonify({
                "message": "Image retrieved successfully",
                "image_url": detail.image_url
            }), 200
        
        # Handle image deletion
        elif request.method == "DELETE":
            query = sqlalchemy.text("SELECT detail_id, image_url FROM Event_Detail WHERE event_id = :event_id")
            result = connection.execute(query, {"event_id": event_id})
            detail = result.fetchone()
            
            if not detail or not detail.image_url:
                cursor.close()
                connection.close()
                return jsonify({"message": "No image found for this event"}), 404
            
            # Delete from GCS
            deleted = delete_file_from_gcs(detail.image_url)
            if not deleted:
                cursor.close()
                connection.close()
                return jsonify({"message": "Failed to delete image from storage"}), 500
            
            # Update database
            update_query = sqlalchemy.text(
                "UPDATE Event_Detail SET image_url = NULL, updated_at = CURRENT_TIMESTAMP WHERE detail_id = :detail_id"
            )
            connection.execute(update_query, {"detail_id": detail.detail_id})
            connection.commit()
            
            cursor.close()
            connection.close()
            return jsonify({"message": "Image deleted successfully"}), 200
    
    except Exception as e:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
        return jsonify({"message": f"Error handling event image: {str(e)}"}), 500
    
    
#endpoint for document handling
@app.route("/events/<int:event_id>/document", methods=["POST", "GET", "DELETE"])
def handle_event_document(event_id):
    # Check if event exists
    connection = get_db_connection()
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Verify the event exists
        query = sqlalchemy.text("SELECT event_id FROM Event WHERE event_id = :event_id")
        result = connection.execute(query, {"event_id": event_id})
        event = result.fetchone()
        
        if not event:
            cursor.close()
            connection.close()
            return jsonify({"message": f"Event with ID {event_id} not found"}), 404
        
        # Handle document upload
        if request.method == "POST":
            # Check if file is in the request
            if 'document' not in request.files:
                cursor.close()
                connection.close()
                return jsonify({"message": "No document file provided"}), 400
            
            file = request.files['document']
            
            # Check if file has a name
            if file.filename == '':
                cursor.close()
                connection.close()
                return jsonify({"message": "No selected file"}), 400
            
            # Check file extension
            allowed_extensions = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt'}
            if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                cursor.close()
                connection.close()
                return jsonify({"message": "Invalid file type. Allowed types: pdf, doc, docx, ppt, pptx, txt"}), 400
            
            # Upload to GCS
            file_url = upload_file_to_gcs(file, folder="event_documents")
            if not file_url:
                cursor.close()
                connection.close()
                return jsonify({"message": "Failed to upload document"}), 500
            
            # Check if there's already a document for this event
            query = sqlalchemy.text("SELECT detail_id, document_url FROM Event_Detail WHERE event_id = :event_id")
            result = connection.execute(query, {"event_id": event_id})
            existing_detail = result.fetchone()
            
            if existing_detail:
                # Update existing record
                old_document_url = existing_detail.document_url
                
                # Delete old document if it exists
                if old_document_url:
                    delete_file_from_gcs(old_document_url)
                
                # Update record
                update_query = sqlalchemy.text(
                    "UPDATE Event_Detail SET document_url = :document_url, updated_at = CURRENT_TIMESTAMP WHERE detail_id = :detail_id"
                )
                connection.execute(update_query, {
                    "document_url": file_url,
                    "detail_id": existing_detail.detail_id
                })
            else:
                # Create new record
                insert_query = sqlalchemy.text(
                    "INSERT INTO Event_Detail (event_id, document_url) VALUES (:event_id, :document_url)"
                )
                connection.execute(insert_query, {
                    "event_id": event_id,
                    "document_url": file_url
                })
            
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({
                "message": "Document uploaded successfully",
                "document_url": file_url
            }), 201
        
        # Handle document retrieval
        elif request.method == "GET":
            query = sqlalchemy.text("SELECT document_url FROM Event_Detail WHERE event_id = :event_id")
            result = connection.execute(query, {"event_id": event_id})
            detail = result.fetchone()
            
            cursor.close()
            connection.close()
            
            if not detail or not detail.document_url:
                return jsonify({"message": "No document found for this event"}), 404
            
            return jsonify({
                "message": "Document retrieved successfully",
                "document_url": detail.document_url
            }), 200
        
        # Handle document deletion
        elif request.method == "DELETE":
            query = sqlalchemy.text("SELECT detail_id, document_url FROM Event_Detail WHERE event_id = :event_id")
            result = connection.execute(query, {"event_id": event_id})
            detail = result.fetchone()
            
            if not detail or not detail.document_url:
                cursor.close()
                connection.close()
                return jsonify({"message": "No document found for this event"}), 404
            
            # Delete from GCS
            deleted = delete_file_from_gcs(detail.document_url)
            if not deleted:
                cursor.close()
                connection.close()
                return jsonify({"message": "Failed to delete document from storage"}), 500
            
            # Update database
            update_query = sqlalchemy.text(
                "UPDATE Event_Detail SET document_url = NULL, updated_at = CURRENT_TIMESTAMP WHERE detail_id = :detail_id"
            )
            connection.execute(update_query, {"detail_id": detail.detail_id})
            connection.commit()
            
            cursor.close()
            connection.close()
            return jsonify({"message": "Document deleted successfully"}), 200
    
    except Exception as e:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
        return jsonify({"message": f"Error handling event document: {str(e)}"}), 500
