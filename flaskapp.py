from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from io import StringIO
import os
import json
import time
from threading import Timer
import mysql.connector
from mysql.connector import Error


app = Flask(__name__)
CORS(app)


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