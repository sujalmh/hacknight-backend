from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declared_attr
from datetime import datetime
from pytz import timezone
from sqlalchemy import Table, Column, Integer, ForeignKey

db = SQLAlchemy()

class Application(db.Model):
    __tablename__ = 'applications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)
    application_date = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))
    status = db.Column(db.String(20), default='pending')
    user = relationship('User', back_populates='applications')
    jobs = relationship('Jobs', back_populates='applications')


class Connection(db.Model):
    __tablename__ = 'connections'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    connected_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    accepted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))


class College(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255))
    website = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))
    users = db.relationship('User', backref='college_students', lazy=True)


# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    profile_photo = db.Column(db.String(40), unique=True, nullable=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    profile_picture = db.Column(db.String(40), unique=True, nullable=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.Integer,nullable=False)
    role = db.Column(db.String(50), default='student')
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))
    college_id = db.Column(db.Integer, db.ForeignKey('college.id'),nullable = True)
    alumni_profile = db.relationship('AlumniProfile', backref='user', uselist=False)
    student_profile = db.relationship('StudentProfile', backref='user', uselist=False)
    applications = db.relationship('Application', back_populates='user')
    @property
    def profile(self):
        if self.role == 'alumni':
            return self.alumni_profile
        else:
            return self.student_profile
    connections_as_user = db.relationship('Connection', foreign_keys=[Connection.user_id], backref='user', cascade='all, delete-orphan')
    connections_as_connected_user = db.relationship('Connection', foreign_keys=[Connection.connected_user_id], backref='connected_user', cascade='all, delete-orphan')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver')

    def get_job_applications(self):
        return [
            {
                "job_name": application.jobs.title,
                "date_applied": application.application_date,
                "status": application.status
            }
            for application in self.applications
        ]

# Profile model
class AlumniProfile(db.Model):
    __tablename__ = 'alumni_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    position = db.Column(db.String(100), nullable=True)
    company = db.Column(db.String(100), nullable=True)
    experience_years = db.Column(db.Integer, nullable=True)
    skills = db.Column(db.String(250), nullable=True)
    linkedin = db.Column(db.String(300), nullable=True)
    resume = db.Column(db.String(100), nullable=True)
    passout_year = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        return {    
            'bio': self.bio,
            'industry': self.industry,
            'experience_years': self.experience_years,
            'skills': self.skills,
            'linkedin': self.linkedin,
            'resume': self.resume,
            'passout_year': self.passout_year
        }


  
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

    def to_dict(self):
        return {    
            'bio': self.bio,
            'interests': self.interests,
            'learning_years': self.learning_years,
            'skills': self.skills,
            'linkedin': self.linkedin,
            'resume': self.resume
        }

# Event model
class Event(db.Model):
    __tablename__ = 'event'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))
    event_name = db.Column(db.String(50), nullable=False)
    event_description = db.Column(db.Text, nullable=False)
    max_participants = db.Column(db.Integer, nullable=False)
    event_date = db.Column(db.DateTime, nullable=False)
    event_time = db.Column(db.Time, nullable=False)
    event_venue = db.Column(db.String(50), nullable=False)
    event_image = db.Column(db.String(100), nullable=True)
    event_created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_applications = db.relationship('EventApplication', backref='event', cascade='all, delete-orphan')
    

    def to_dict(self):
        return {
            'event_name': self.event_name,
            'event_description': self.event_description,
            'max_participants': self.max_participants,
            'event_date': self.event_date,
            'event_time': self.event_time,
            'event_venue': self.event_venue,
            'event_created_by': self.event_created_by,
            'event_image': self.event_image
        }
    
class EventApplication(db.Model):
    __tablename__ = 'event_applications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    

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

class Jobs(db.Model):
    __tablename__ = 'jobs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    company = db.Column(db.String(150), nullable=False)
    required_skills = db.Column(db.String(150), nullable=False)
    location = db.Column(db.String(150), nullable=True)
    posted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))
    applications = relationship('Application', back_populates='jobs')

class Notifications(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone("Asia/Kolkata")))

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    passout_year = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref='announcements')

    def __repr__(self):
        return f'<Announcement {self.title}>'



