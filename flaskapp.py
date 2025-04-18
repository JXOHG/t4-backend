from flask import Flask, request, jsonify, send_file, session, request, url_for, redirect
from flask_cors import CORS
from io import StringIO
from functools import wraps
import os
import json
from threading import Timer
import mysql.connector
from mysql.connector import Error
from datetime import datetime
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

# Database connection using MySQL Connector
def get_db_connection():
    try:

        # Connect using the Cloud SQL connector

        conn = connector.connect(
            "t4-backend:northamerica-northeast2:t4-backend-sql",
            "pymysql",
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASS'),
            db=os.getenv('DB_NAME')
        )
        return conn
    except Exception as e:
        print(f"Error connecting to Cloud SQL: {e}")

        return None
    

@app.route("/test-database", methods=["GET"])
def test_database_connection():
    connection = get_db_connection()
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500

    cursor = connection.cursor(pymysql.cursors.DictCursor)
    
    try:
        # Test query
        query = "SELECT * FROM User LIMIT 5"
        #query = "SHOW PROCEDURE STATUS WHERE db = 'events'"
        # Execute the query
        cursor.execute(query)
        
        # Fetch all results
        results = cursor.fetchall()
        

        return jsonify({
            "message": "Database connection successful",
            "users": results,
            "user_count": len(results)
        }), 200

    except Exception as e:
        return jsonify({
            "message": "Error querying database",
            "error": str(e)
        }), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
        
        
@app.route("/events", defaults={"event_id": None}, methods=["GET", "POST"])
@app.route("/events/<int:event_id>", methods=["GET", "PUT", "DELETE"])

def events(event_id = None):
    connection = get_db_connection()
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    cursor = connection.cursor(pymysql.cursors.DictCursor)
        
    if request.method == 'GET':
        # Return upcoming events
        if event_id is None:
            try:
                cursor.callproc("GetUpcomingEvents")
                rows = cursor.fetchall()
                return jsonify({"message": rows}), 200
            except Exception as e:
                return jsonify({"message": f"error calling all events: {str(e)}"}), 401
            finally:
                cursor.close()
                connection.close()
                
        # Return event with given event id
        try:
            cursor.callproc("GetEventDetails", (event_id,) )
            row = cursor.fetchall()
            return jsonify({"message": row}), 200
        except Exception as e:
            return jsonify({"message": f"error fetching event: {str(e)}"}), 401
        finally:
            cursor.close()
            connection.close() 

    elif request.method == 'POST':
        # Create a new event
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
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"Missing data: {str(e)}"}), 400
        
        try:
            # Example input: 'Mon, 15 Jul 2025 00:00:00 GMT'
            parsed_event_date = datetime.strptime(eventDate, "%a, %d %b %Y %H:%M:%S GMT")
            formatted_event_date = parsed_event_date.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"Invalid date format: {str(e)}"}), 400
        
        cursor.callproc("CreateEvent",(title, description, formatted_event_date, location,))
        connection.commit()

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"message": "An error occurred"}), 500

    finally:
        cursor.close()
        connection.close()

        return jsonify({"message": "Created event"}), 201
        
    # Update existing event    
    elif request.method == 'PUT':
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
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"Missing data: {str(e)}"}), 400
        
        try:
            # Example input: 'Mon, 15 Jul 2025 00:00:00 GMT'
            parsed_event_date = datetime.strptime(eventDate, "%a, %d %b %Y %H:%M:%S GMT")
            formatted_event_date = parsed_event_date.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({"message": f"Invalid date format: {str(e)}"}), 400
        
        try:
            cursor.callproc("UpdateEvent",(event_id, title, description, formatted_event_date, location,))
            connection.commit()
            return jsonify({"message": "Updated event"}), 200
        except Exception as e:
            return jsonify({"message": f"error updating event: {str(e)}"}), 401 
        finally:
            cursor.close()
            connection.close()
            
    # Delete existing event
    elif request.method == 'DELETE':
        try:
            cursor.callproc("DeleteEvent",(event_id,))
            connection.commit()      
            return jsonify({"message": f"deleted event {event_id}"}), 200
        except Exception as e:
            return jsonify({"message": f"event cannot be deleted, Error: {e}"}), 401
        finally:
            cursor.close()
            connection.close()
    
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
    connection = get_db_connection()  # Establish a database connection
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    
    if request.method == "GET":
        # Returns all users
        if id is None:    
            try:
                cursor.callproc("GetAllUsers",)
                rows = cursor.fetchall()
                return jsonify({"message": rows}), 200
            except Exception as e:
                return jsonify({"message": f"unable to get all users, Error: {e}"}), 400
            finally:
                cursor.close()
                connection.close()
        
        # Returns specific user
        try:
            cursor.callproc("GetUserByID", (id,))
            row = cursor.fetchall()
            return jsonify({"message": row}), 200
        except:
            return jsonify({"message": f"unable to get data on id: {id}"}), 400
        finally:
            cursor.close()
            connection.close()
            
    # Edits existing user
    if request.method == "PUT":
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON or missing Content-Type"}), 400
        try:
            cursor.callproc("UpdateUser", (id, data["first_name"], data["last_name"], data["email"],))
            connection.commit() 
            return jsonify({"message": "user info updated"}), 200
        except Exception as e:
            return jsonify({"message": f"unable to update user info: {str(e)}"}), 401 
        finally:
            cursor.close()
            connection.close()
    
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
    if not (user_email == "sales.club@westernusc.ca" or "westernsalesclub@gmail.com" or "justinohg121@gmail.com"):
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
    try:
        # Reset file pointer to beginning
        file.seek(0)
        
        # Generate a secure filename with a UUID
        original_filename = secure_filename(file.filename)
        filename_parts = original_filename.rsplit('.', 1)
        
        if len(filename_parts) > 1:
            ext = filename_parts[1].lower()
            unique_filename = f"{uuid.uuid4().hex}.{ext}"
        else:
            unique_filename = f"{uuid.uuid4().hex}"
            
        # Path in the bucket
        destination_blob_name = f"{folder}/{unique_filename}"
        
        # Get the storage client and bucket
        storage_client = get_storage_client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)
        
        # Upload the file
        blob.upload_from_file(file, content_type=file.content_type)
        
        # Instead of make_public() for uniform bucket-level access:
        # Just construct the public URL based on the bucket and object name
        public_url = f"https://storage.googleapis.com/{bucket_name}/{destination_blob_name}"
        
        return public_url
    
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
    connection = get_db_connection()
    if connection is None:
        return jsonify({"message": "Database connection failed"}), 500

    cursor = connection.cursor(pymysql.cursors.DictCursor)
    
    try:
        # Verify the event exists
        query = "SELECT event_id FROM Event WHERE event_id = %s"
        cursor.execute(query, (event_id,))
        event = cursor.fetchone()
        

        if not event:
            cursor.close()
            connection.close()
            return jsonify({"message": f"Event with ID {event_id} not found"}), 404

        # 2. Handle POST - Upload image
        if request.method == "POST":
            if 'image' not in request.files:
                cursor.close()
                connection.close()
                return jsonify({"message": "No image file provided"}), 400

            file = request.files['image']

            if file.filename == '':
                cursor.close()
                connection.close()
                return jsonify({"message": "No selected file"}), 400

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
            query = "SELECT detail_id, image_url FROM Event_Detail WHERE event_id = %s"
            cursor.execute(query, (event_id,))
            existing_detail = cursor.fetchone()
            
            if existing_detail:
                # Update existing record
                old_image_url = existing_detail["image_url"]
                
                # Delete old image if it exists
                if old_image_url:
                    delete_file_from_gcs(old_image_url)
                
                # Update record
                update_query = "UPDATE Event_Detail SET image_url = %s, updated_at = CURRENT_TIMESTAMP WHERE detail_id = %s"
                
                cursor.execute(update_query, (file_url, existing_detail["detail_id"],))
            else:
                # Create new record
                insert_query = "INSERT INTO Event_Detail (event_id, image_url) VALUES (%s, %s)"
                cursor.execute(insert_query, (event_id, file_url,))
            

            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({"message": "Image uploaded successfully", "image_url": file_url}), 201

        # 3. Handle GET - Retrieve image
        elif request.method == "GET":

            query = "SELECT image_url FROM Event_Detail WHERE event_id = %s"
            cursor.execute(query, (event_id,))
            detail = cursor.fetchone()
            
            cursor.close()
            connection.close()
            

            if not detail or not detail["image_url"]:
                return jsonify({"message": "No image found for this event"}), 404

            return jsonify({
                "message": "Image retrieved successfully",
                "image_url": detail["image_url"]
            }), 200

        # 4. Handle DELETE - Remove image
        elif request.method == "DELETE":

            query = "SELECT detail_id, image_url FROM Event_Detail WHERE event_id = %s"
            cursor.execute(query, (event_id,))
            detail = cursor.fetchone()
            

            if not detail or not detail["image_url"]:
                cursor.close()
                connection.close()
                return jsonify({"message": "No image found for this event"}), 404

            
            # Delete from GCS

            deleted = delete_file_from_gcs(detail["image_url"])
            if not deleted:
                cursor.close()
                connection.close()
                return jsonify({"message": "Failed to delete image from storage"}), 500

            
            # Update database
            update_query = "UPDATE Event_Detail SET image_url = NULL, updated_at = CURRENT_TIMESTAMP WHERE detail_id = %s"
            cursor.execute(update_query, (detail["detail_id"],))

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
    
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    
    try:
        # Verify the event exists

        query = "SELECT event_id FROM Event WHERE event_id = %s"
        cursor.execute(query, (event_id,))

        event = cursor.fetchone()
        
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

            query = "SELECT detail_id, document_url FROM Event_Detail WHERE event_id = %s"
            cursor.execute(query, (event_id,))

            existing_detail = cursor.fetchone()
            
            if existing_detail:
                # Update existing record

                old_document_url = existing_detail["document_url"]

                
                # Delete old document if it exists
                if old_document_url:
                    delete_file_from_gcs(old_document_url)
                
                # Update record

                update_query = "UPDATE Event_Detail SET document_url = %s, updated_at = CURRENT_TIMESTAMP WHERE detail_id = %s"
                cursor.execute(update_query, (file_url, existing_detail["detail_id"],))
            else:
                # Create new record
                insert_query = "INSERT INTO Event_Detail (event_id, document_url) VALUES (%s, %s)"
                
                cursor.execute(insert_query, (event_id, file_url,))

            
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({
                "message": "Document uploaded successfully",
                "document_url": file_url
            }), 201
        
        # Handle document retrieval
        elif request.method == "GET":

            query = "SELECT document_url FROM Event_Detail WHERE event_id = %s"
            cursor.execute(query, (event_id,))

            detail = cursor.fetchone()
            
            cursor.close()
            connection.close()
            

            if not detail or not detail["document_url"]:

                return jsonify({"message": "No document found for this event"}), 404
            
            return jsonify({
                "message": "Document retrieved successfully",

                "document_url": detail["document_url"]

            }), 200
        
        # Handle document deletion
        elif request.method == "DELETE":

            query = "SELECT detail_id, document_url FROM Event_Detail WHERE event_id = %s"
            cursor.execute(query, (event_id,))
            detail = cursor.fetchone()
            
            if not detail or not detail["document_url"]:

                cursor.close()
                connection.close()
                return jsonify({"message": "No document found for this event"}), 404
            
            # Delete from GCS

            deleted = delete_file_from_gcs(detail["document_url"])

            if not deleted:
                cursor.close()
                connection.close()
                return jsonify({"message": "Failed to delete document from storage"}), 500
            
            # Update database

            update_query = "UPDATE Event_Detail SET document_url = NULL, updated_at = CURRENT_TIMESTAMP WHERE detail_id = %s"
            
            cursor.execute(update_query, (detail["detail_id"],))

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
    
if __name__ == '__main__':
    app.run(debug= True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
