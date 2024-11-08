from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask_migrate import Migrate
from models import db, User, Message, AlumniProfile, StudentProfile, Connection,College

# Initialize the app
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'Num3R0n4u7s!Num3R0n4u7s!'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=6)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
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
    name = data.get('name')
    phone_number = data.get('phone_number')
    email = data.get('email')
    role = data.get('role')

    user_exists = User.query.filter((User.username == username or User.email == email  )).first()
    if user_exists:
        return jsonify({"message": "User with that username or email already exists"}), 400

    hashed_password = generate_password_hash(password)
    user = User(username=username, password=hashed_password, name=name, phone_number=phone_number, email=email, role=role)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Login route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))

    return jsonify(access_token=access_token), 200

@app.route('/api/register/admin', methods=['POST'])
def register_admin():
    data = request.get_json()
    required_fields = ['name', 'email', 'password', 'secret_key']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Field '{field}' is required"}), 400

    SECRET_ADMIN_KEY = "my_secure_key"
    if data['secret_key'] != SECRET_ADMIN_KEY:
        return jsonify({"error": "Invalid secret key"}), 403
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email is already registered"}), 400
    hashed_password = generate_password_hash(data['password'], method='sha256')
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

@app.route('/api/add_college', methods=['POST'])
@jwt_required()
def add_college():
    current_user = get_jwt_identity()
    user = User.query.filter_by(id=current_user).first()
    if user.role != 'college':
        return jsonify({"error": "Only users with college role can add colleges."}), 400
    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    website = data.get('website')
    try:
        college = College(name=name, address=address, website=website)
        db.session.add(college)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 400
    return jsonify({"message": "College added successfully"}), 201


@app.route('/api/profile/student', methods=['POST'])
@jwt_required()
def create_student_profile():
    data = request.get_json()

    current_user = get_jwt_identity()

    user = User.query.get(current_user)
    if user.role != 'student':
        return jsonify({"error": "Only students can create student profiles"}), 400

    new_profile = StudentProfile(
        user_id=current_user,
        bio=data.get('bio', ''),
        interests=data.get('interests', ''),
        learning_years=data.get('learning_years', ''),
        skills=data.get('skills', ''),
        linkedin=data.get('linkedin',''),
        resume=data.get('resume', '')
    )
    db.session.add(new_profile)
    db.session.commit()

    return jsonify({"message": "Student profile created successfully"}), 201

@app.route('/api/profile/alumni', methods=['POST'])
@jwt_required()
def create_alumni_profile():
    data = request.get_json()

    current_user = get_jwt_identity() 

    user = User.query.get(current_user)
    if user.role != 'alumni':
        return jsonify({"error": "Only alumni can create alumni profiles"}), 400

    new_profile = AlumniProfile(
        user_id=current_user,
        bio=data.get('bio', ''),
        industry=data.get('industry', ''),
        experience_years=data.get('experience_years', ''),
        skills=data.get('skills', ''),
        linkedin=data.get('linkedin',''),
        resume=data.get('resume', '')
    )
    db.session.add(new_profile)
    db.session.commit()

    return jsonify({"message": "Alumni profile created successfully"}), 201


@app.route('/api/<int:user_id>/send_message/<int:receiver_id>', methods=['POST'])
def send_message(user_id, receiver_id):
    user = User.query.get(user_id)
    receiver = User.query.get(receiver_id)
    data = request.get_json()
    if not user or not receiver:
        return jsonify({'message': 'Invalid sender or receiver ID'}), 400
    
    content = data.get('content')

    message = Message(sender_id=user_id, receiver_id=receiver_id, content=content)
    db.session.add(message)
    db.session.commit()
    return jsonify({'message': 'Message sent successfully'}), 201

@app.route('/api/<int:user_id>/chat_staus/<int:reciever_id>', methods=['POST'])
def chat_status(user_id, reciever_id):
    user = User.query.get(user_id)
    receiver = User.query.get(reciever_id)
    if not user or not receiver:
        return jsonify({'message': 'Invalid sender or receiver ID'}), 400
    messages = Message.query.filter_by(sender_id=user_id,receiver_id=reciever_id,status=0).all()
    if not messages:
        return jsonify({'message': 'Message not found'}), 404
    for message in messages:
        message.status = 1
    db.session.commit()
    return jsonify({'message': 'Message status updated successfully'}), 200

@app.route('/api/<int:user1_id>/get_chat/<int:user2_id>', methods=['GET'])
def get_chat(user1_id, user2_id):
    messages = Message.query.filter(
        ((Message.sender_id == user1_id) & (Message.receiver_id == user2_id)) |
        ((Message.sender_id == user2_id) & (Message.receiver_id == user1_id))
    ).order_by(Message.timestamp).all()

    chat_history = [
        {
            'sender_id': message.sender_id,
            'reciever_id': message.receiver_id,
            'content': message.content,
            'timestamp': message.timestamp
        } for message in messages
    ]
    return jsonify(chat_history), 200


# Run the app
if __name__ == '__main__':
    app.run(debug=True)
