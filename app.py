from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from functools import wraps
from models import db, User

# Initialize the app
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'Num3R0n4u7s!Num3R0n4u7s!'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=6)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Create tables within app context
with app.app_context():
    db.create_all()  

# Register route
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user_exists = User.query.filter((User.username == username)).first()
    if user_exists:
        return jsonify({"message": "User with that username or email already exists"}), 400
    print(password)
    hashed_password = generate_password_hash(password)
    user = User(username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Login route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=data['username']).first()

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))

    return jsonify(access_token=access_token), 200

# Protected route example
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected_route():
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)
    
    return jsonify({'message': f'Hello, {user.username}! This is a protected route.'}), 200

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
