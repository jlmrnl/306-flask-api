from bson import ObjectId
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import jwt
from functools import wraps

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb+srv://jlmrnl001:JAusi1Aaic0ndIRR@cluster0.m34jzxm.mongodb.net/test'
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'api123'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token.split(' ')[1], app.config['SECRET_KEY'])
        except:
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
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = mongo.db.users.find_one({'username': data['username']})

    if user and bcrypt.check_password_hash(user['password'], data['password']):
        token = jwt.encode({'id': str(user['_id'])}, app.config['SECRET_KEY'])
        return jsonify({'token': token, 'message': 'Login successful'}), 200

    return jsonify({'message': 'Invalid username or password'}), 401p

@app.route('/notes', methods=['GET'])
@token_required
def get_notes(current_user):
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

@app.route('/notes/<string:id>', methods=['DELETE'])
@token_required
def delete_note(current_user, id):
    note = mongo.db.notes.find_one({'_id': ObjectId(id), 'user': current_user['id']})
    if note:
        mongo.db.notes.delete_one({'_id': ObjectId(id)})
        return jsonify({'message': 'Note deleted successfully'}), 200
    return jsonify({'message': 'Note not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
