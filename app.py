from bson import ObjectId
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import jwt
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb+srv://jlmrnl001:JAusi1Aaic0ndIRR@cluster0.m34jzxm.mongodb.net/test'
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'api123'
CORS(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            token = token.split(' ')[1]  # Extract the token part (if needed)
            print("Received token:", token)  # Add this line to check the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            print("Token validation error:", str(e))  # Print any token validation errors
            return jsonify({'message': 'Token is invalid'}), 401

        return f(data, *args, **kwargs)

    return decorated


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = {
        'username': data['username'],
        'password': hashed_password
    }
    mongo.db.users.insert_one(user)

    # Generate and return the token
    token = jwt.encode({'id': str(user['_id'])}, app.config['SECRET_KEY'])

    return jsonify({'token': token, 'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = mongo.db.users.find_one({'username': data['username']})

    if user and bcrypt.check_password_hash(user['password'], data['password']):
        token = jwt.encode({'id': str(user['_id'])}, app.config['SECRET_KEY'])
        return jsonify({'token': token, 'message': 'Login successful'}), 200

    return jsonify({'message': 'Invalid username or password'}, 401)

@app.route('/notes', methods=['GET'])
@token_required
def get_notes(current_user):
    print("Current user:", current_user)  # Add this line to log the current user
    notes = list(mongo.db.notes.find({'user': current_user['id']}))
    for note in notes:
        note['_id'] = str(note['_id'])
    return jsonify(notes), 200

@app.route('/notes', methods=['POST'])
@token_required
def create_note(current_user):
    data = request.get_json()
    note = {
        'user': current_user['id'],
        'title': data['title'],
        'note': data['note']
    }
    mongo.db.notes.insert_one(note)
    return jsonify({'message': 'Note created successfully'}), 201


@app.route('/notes/<string:id>', methods=['PUT'])
@token_required
def update_note(current_user, id):
    data = request.get_json()
    updated_note = {
        'user': current_user['id'],
        'title': data['title'],
        'note': data['note']
    }

    # Check if the note exists and belongs to the current user
    existing_note = mongo.db.notes.find_one({'_id': ObjectId(id), 'user': current_user['id']})
    if existing_note:
        # Update the note with the new data
        mongo.db.notes.update_one({'_id': ObjectId(id)}, {'$set': updated_note})
        return jsonify({'message': 'Note updated successfully'}), 200
    return jsonify({'message': 'Note not found or unauthorized'}, 404)

@app.route('/notes/<string:id>', methods=['DELETE'])
@token_required
def delete_note(current_user, id):
    note = mongo.db.notes.find_one({'_id': ObjectId(id), 'user': current_user['id']})
    if note:
        mongo.db.notes.delete_one({'_id': ObjectId(id)})
        return jsonify({'message': 'Note deleted successfully'}), 200
    return jsonify({'message': 'Note not found or unauthorized'}, 404)

if __name__ == '__main__':
    app.run(debug=True)