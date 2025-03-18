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