from flask import Flask, request, jsonify, json, send_from_directory
import os
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from functools import wraps
from models import db, User, Message, AlumniProfile, StudentProfile, Connection,College,Event,Jobs,Application
from werkzeug.utils import secure_filename
#from extract import get_about, get_experiences, get_profile_photo, get_skills
from sqlalchemy.sql.expression import func

# Initialize the app
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'Num3R0n4u7s!Num3R0n4u7s!'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=6)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'files/'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024


# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "http://localhost:5173"}})

# Create tables within app context
with app.app_context():
    db.create_all()  

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_resume_by_application(application_id):
    application = Application.query.get(application_id)
    
    if not application:
        return {"error": "Application not found"}
    
    # Retrieve the user associated with the application
    user = application.user
    
    resume = user.profile.resume if user.profile else None
    
    if resume:
        return resume
    else:
        return 'Resume not found'

# Register route
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    phone_number = data.get('phone_number')
    email = data.get('email')
    role = data.get('role').lower()

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
    current_user = get_jwt_identity()

    json_data = request.form.get('json_data')
    if json_data:
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format"}), 400
    else:
        return jsonify({"error": "No JSON data provided"}), 400

    user = User.query.get(current_user)

    if user.role != 'student':
        return jsonify({"error": "Only students can create student profiles"}), 400
    
    if 'resume' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    resume_file = request.files['resume']
    resume = None

    if allowed_file(resume_file.filename):
        unique_filename = f"{user.username}_{resume_file.filename}"
        resume_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resumes/', unique_filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        resume_file.save(resume_path)
        resume = resume_path 

    else:
        jsonify({"error": "Invalid file format or file too large."}), 413 

    try:
        new_profile = StudentProfile(
        user_id=current_user,
        bio=data.get('bio', ''),
        interests=data.get('interests', ''),
        learning_years=data.get('learning_years', ''),
        skills=data.get('skills', ''),
        linkedin=data.get('linkedin',''),
        resume=resume
        
        )
        db.session.add(new_profile)
        db.session.commit()
        return jsonify({"message": "Student profile created successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 400

@app.route('/api/profile/alumni', methods=['POST'])
@jwt_required()
def create_alumni_profile():
    current_user = get_jwt_identity() 

    json_data = request.form.get('json_data')
    if json_data:
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format"}), 400
    else:
        return jsonify({"error": "No JSON data provided"}), 400

    user = User.query.get(current_user)
    if user.role != 'alumni':
        return jsonify({"error": "Only alumni can create alumni profiles"}), 400
    
    if 'resume' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    resume_file = request.files['resume']
    resume = None

    if allowed_file(resume_file.filename):
        unique_filename = f"{user.username}_{resume_file.filename}"
        resume_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        resume_file.save(resume_path)
        resume = resume_path 

    else:
        jsonify({"error": "Invalid file format or file too large."}), 413  

    new_profile = AlumniProfile(
        user_id=current_user,
        bio=data.get('bio', ''),
        industry=data.get('industry', ''),
        experience_years=data.get('experience_years', ''),
        skills=data.get('skills', ''),
        linkedin=data.get('linkedin',''),
        resume= resume
    )
    db.session.add(new_profile)
    db.session.commit()

    return jsonify({"message": "Alumni profile created successfully"}), 201

@app.route('/api/view_profile/<int:user_id>', methods=['GET'])
def view_profile(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if user.role == 'student':
        profile = StudentProfile.query.filter_by(user_id=user_id).first()
    elif user.role == 'alumni':
        profile = AlumniProfile.query.filter_by(user_id=user_id).first()
    if not profile:
        return jsonify({'message': 'Profile not found'}), 404
    
    return jsonify(profile.to_dict())


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
@jwt_required()
def get_chat(user1_id, user2_id):
    current_user = get_jwt_identity()
    if current_user != user1_id:
        return jsonify({'message': 'Unauthorized access'}), 401
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

@app.route("/api/explore", methods=['GET'])
@jwt_required()
def explore():
    alumni = User.query.filter_by(role='alumni').order_by(func.random()).limit(10).all()
    alumni_data = [
        {
            "id": alumnus.id,
            "name": alumnus.name,
            "email": alumnus.email,
            "profile_photo": alumnus.profile_photo,
            "industry": alumnus.profile.industry
        }
        for alumnus in alumni
    ]
    return jsonify(alumni_data), 200

@app.route("/api/send_connection/<int:user1_id>/<int:user2_id>", methods=['POST'])
@jwt_required()
def send_connection(user1_id, user2_id):
    current_user = get_jwt_identity()
    if user1_id!=current_user:
        return jsonify({"error": "You can only send connection requests on your own behalf"}), 400
    user = User.query.get(user1_id)
    reciever = User.query.get(user2_id)
    if not user or not reciever:
        return jsonify({"error": "Invalid user ID"}), 400
    connection = Connection(user_id=user1_id, connected_user_id=user2_id)
    db.session.add(connection)
    db.session.commit()
    return jsonify({"message": "Connection request sent successfully"}), 201

@app.route("/api/invitations", methods=['GET'])
@jwt_required()
def invitations():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    if user.role != 'alumni':
        return jsonify({"error": "Only alumni can view connection requests"}), 400
    
    connection_data = []
    connections = Connection.query.filter_by(connected_user_id=user.id, accepted=False).all()
    for connection in connections:
        con_user = User.query.get(connection.user_id)
        connection_data.append({
            'id': con_user.id,
            'name': con_user.name,
        })
    return jsonify(connection_data), 200

@app.route("/api/accept_invitation/<int:user_id>", methods=['POST'])
@jwt_required()
def accept_invitation(user_id):
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    
    if user.role != 'alumni':
        return jsonify({"error": "Only alumni can view connection requests"}), 400
    
    sender = User.query.get(user_id)
    
    connection = Connection.query.filter_by(user_id=sender.id, connected_user_id=current_user).first()
    connection.accepted = True
    db.session.commit()
    return jsonify({"message": "Connection request accepted"}), 200

@app.route("/api/connections", methods=['GET'])
@jwt_required()
def connections():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    connections = Connection.query.filter(
        (Connection.user_id == user.id) | (Connection.connected_user_id == user.id),
        Connection.accepted == True
    ).all()

    connection_data = []
    for connection in connections:
        con_user_id = -1
        if connection.user_id == user.id:
            con_user_id = connection.connected_user_id
        else:
            con_user_id = connection.user_id
        con_user = User.query.get(con_user_id)
        connection_data.append({
            'id': con_user.id,
            'name': con_user.name
        })
    return jsonify(connection_data), 200

@app.route('/api/alumni/create_event', methods=['POST'])
@jwt_required()
def create_event_alumni():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    if user.role != 'alumni':
        return jsonify({"error": "Only alumni can create events"}), 400
    data = request.get_json()
    event_image = data.get('event_image')
    event_name = data.get('event_name')
    event_description = data.get('event_description')
    max_participants = data.get('max_participants')
    event_date = data.get('event_date')
    event_time = data.get('event_time')
    event_venue = data.get('event_venue')

    if not event_name or not event_description or not max_participants or not event_date or not event_time or not event_venue:
        return jsonify({"error": "All fields are required"}), 400
    try:
        event = Event(title=event_name, description=event_description, max_participants=max_participants, event_date=event_date, event_time=event_time, event_venue=event_venue)
        db.session.add(event)
        db.session.commit()
        return jsonify({"message": "Event created successfully"}), 201
    except Exception as e:  
        db.session.rollback()
        return jsonify({"message": str(e)}), 400

@app.route('/api/alumni/create_job', methods=['POST'])
@jwt_required()
def create_job_alumni():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    if user.role != 'alumni':
        return jsonify({"error": "Only alumni can create jobs"}), 400

    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    location = data.get('location')
    company = data.get('company')
    required_skills = data.get('required_skills')

    if not title or not description or not location or not company or not required_skills:
        return jsonify({"error": "All fields are required"}), 400

    try:
        job = Jobs(title=title, description=description, location=location, company=company, required_skills=required_skills,posted_by=current_user)
        db.session.add(job)
        db.session.commit()
        return jsonify({"message": "Job created successfully"}), 201
    except Exception as e:
        db.session.rollback()    
        return jsonify({"message": str(e)}), 400
    
@app.route('/api/alumni/get_applicants/<int:job_id>', methods=['GET'])
def get_applicants(job_id):
    job = Jobs.query.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    applications = Application.query.filter_by(job_id=job_id).all()
    applicant_data = []
    for application in applications:
        
        applicant = StudentProfile.query.get(application.user_id)
        if applicant:
            applicant_data.append({
                'id': applicant.id,
                'name':applicant.user.name,
                'skills': applicant.skills, 
                'resume': get_resume_by_application(applicant.id)
            })
    return jsonify(applicant_data), 200

@app.route('/api/download_resume/<int:user_id>', methods=['GET'])
def download_resume(user_id):
    applicant = StudentProfile.query.get(user_id)
    
    if not applicant or not applicant.resume:
        return jsonify({"error": "Resume not found"}), 404

    base = os.getcwd()
    resume_path = base+'/'+applicant.resume

    if not os.path.isfile(resume_path):
        return jsonify({"error": "Resume file not found"}), 404
    return send_from_directory(base, applicant.resume, as_attachment=True)


    


@app.route('/api/student/apply_job/<int:job_id>', methods=['POST'])
@jwt_required()
def apply_job(job_id):
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    if user.role != 'student':
        return jsonify({"error": "Only students can apply for jobs"}), 400
    job = Jobs.query.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    try:
        new_application = Application(user_id=current_user, job_id=job_id)
        db.session.add(new_application)
        db.session.commit()
        return jsonify({"message": "Job applied successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 400
    
@app.route('/api/get_job_applications', methods=['GET'])
@jwt_required()
def get_job_applications():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    if user.role != 'student':
        return jsonify({"error": "Only students can view job applications"}), 400
    applications = user.get_job_applications()
    if not applications:
        return jsonify({"error": "No job applications found"}), 404
    return jsonify(applications),200


@app.route('/api/get_recent_chat/<int:other_user_id>', methods=['GET'])
@jwt_required()
def get_recent_chat(other_user_id):
    current_user = get_jwt_identity()

    message = Message.query.filter(
        ((Message.sender_id == current_user) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user))
    ).order_by(Message.timestamp.desc()).first()

    if not message:
        return jsonify({'message': ''})

    return jsonify({'message': str(message.content)}), 200

if __name__ == '__main__':
    app.run(debug=True)
