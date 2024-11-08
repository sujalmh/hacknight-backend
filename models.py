from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declared_attr
from datetime import datetime
from pytz import timezone

db = SQLAlchemy()

class Connection(db.Model):
    __tablename__ = 'connections'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    connected_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    accepted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    profile_photo = db.Column(db.String(40), unique=True, nullable=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.Integer,nullable=False)
    role = db.Column(db.String(50), default='student')
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))
    college_id = db.Column(db.Integer, db.ForeignKey('college.id'),nullable = True)
    
    @declared_attr
    def profile(cls):
        if cls.role == 'alumni':
            return relationship('AlumniProfile', backref='user', uselist=False)
        else:
            return relationship('StudentProfile', backref='user', uselist=False)

    connections_as_user = db.relationship('Connection', foreign_keys=[Connection.user_id], backref='user', cascade='all, delete-orphan')
    connections_as_connected_user = db.relationship('Connection', foreign_keys=[Connection.connected_user_id], backref='connected_user', cascade='all, delete-orphan')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver')

# Profile model
class AlumniProfile(db.Model):
    __tablename__ = 'alumni_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    industry = db.Column(db.String(100), nullable=True)
    experience_years = db.Column(db.Integer, nullable=True)
    skills = db.Column(db.String(250), nullable=True)
    linkedin = db.Column(db.String(300), nullable=True)
    resume = db.Column(db.String(100), nullable=True)

class StudentProfile(db.Model):
    __tablename__ = 'student_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    interests = db.Column(db.String(100), nullable=True)
    learning_years = db.Column(db.Integer, nullable=True)
    skills = db.Column(db.String(250), nullable=True)
    linkedin = db.Column(db.String(300), nullable=True)
    resume = db.Column(db.String(100), nullable=True)

class College(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255))
    website = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))
    users = db.relationship('User', backref='college', lazy=True)

# Job model
class Job(db.Model):
    __tablename__ = 'jobs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    company = db.Column(db.String(150), nullable=False)
    location = db.Column(db.String(150), nullable=True)
    posted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))

# Event model
class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(150), nullable=True)
    organizer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# Mentorship model
class Mentorship(db.Model):
    __tablename__ = 'mentorships'
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    mentee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')  # 'pending', 'active', 'completed'
    started_at = db.Column(db.DateTime, nullable=True)
    ended_at = db.Column(db.DateTime, nullable=True)

# Connection model (many-to-many self-reference)


# Message model
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.Integer, nullable=False, default=0)
    react = db.Column(db.String(10), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    



class AdminAnalytics(db.Model):
    __tablename__ = 'admin_analytics'
    id = db.Column(db.Integer, primary_key=True)
    metric_name = db.Column(db.String(150), nullable=False)
    metric_value = db.Column(db.Float, nullable=False)
    recorded_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))
