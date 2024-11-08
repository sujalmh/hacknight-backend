from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from functools import wraps
from models import db, User, Message, Connection

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

<<<<<<< HEAD
# Register route
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    user_exists = User.query.filter((User.username == username)).first()
    if user_exists:
        return jsonify({"message": "User with that username or email already exists"}), 400
    print(password)
    hashed_password = generate_password_hash(password)
    user = User(username=username, password=hashed_password, role=role)
    db.session.add(user)
    db.session.commit()
=======

>>>>>>> 2740b30b491865386a582d44e02e79c0f281d4c4

@app.route('/api/user/<int:user_id>send_message/<int:receiver_id>', methods=['POST'])
def send_message(user_id, receiver_id):
    sender = User.query.get(user_id)
    receiver = User.query.get(receiver_id)
    if not sender or not receiver:
        return jsonify({'message': 'Invalid sender or receiver ID'}), 400
    data = request.get_json()
    content = data.get('content')

    message = Message(sender_id=user_id, receiver_id=receiver_id, content=content)
    db.session.add(message)
    db.session.commit()
    return jsonify({'message': 'Message sent successfully'}), 201

<<<<<<< HEAD
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))

    return jsonify(access_token=access_token), 200

@app.route('/api/register/admin', methods=['POST'])
def register_admin():
    data = request.get_json()

    # Validate required fields
    required_fields = ['name', 'email', 'password', 'secret_key']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Field '{field}' is required"}), 400

    # Check the secret key (this should be kept secure in your configuration)
    SECRET_ADMIN_KEY = "my_secure_key"  # Replace this with an environment variable or config setting
    if data['secret_key'] != SECRET_ADMIN_KEY:
        return jsonify({"error": "Invalid secret key"}), 403

    # Check if the email is unique
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email is already registered"}), 400

    # Hash the password
    hashed_password = generate_password_hash(data['password'], method='sha256')

    # Create the admin user
    admin_user = User(
        name=data['name'],
        email=data['email'],
        password=hashed_password,
        role='admin'
    )
    db.session.add(admin_user)
    db.session.commit()

    return jsonify({
        "message": "Admin registered successfully",
        "user": {
            "id": admin_user.id,
            "name": admin_user.name,
            "email": admin_user.email,
            "role": admin_user.role
        }
    }), 201
=======
@app.route('/api/<int:user1_id>/get_chat/<int:user2_id>', methods=['GET'])
def get_chat(user1_id, user2_id):
    messages = Message.query.filter(
        ((Message.sender_id == user1_id) & (Message.receiver_id == user2_id)) |
        ((Message.sender_id == user2_id) & (Message.receiver_id == user1_id))
    ).order_by(Message.timestamp).all()
>>>>>>> 2740b30b491865386a582d44e02e79c0f281d4c4

    chat_history = [
        {
            'sender_id': message.sender_id,
            'content': message.content,
            'timestamp': message.timestamp
        } for message in messages
    ]
    return jsonify(chat_history), 200
# Run the app
if __name__ == '__main__':
    app.run(debug=True)
