from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    template_id = db.Column(db.Integer, db.ForeignKey('template.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    emails = db.relationship('Email', backref='campaign', lazy=True)

class Template(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    html_content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    role = db.Column(db.String(20), default='employee')  # admin, employee
    department = db.Column(db.String(100))
    progress = db.Column(db.Float, default=0.0)  # Training progress
    login_key = db.Column(db.String(64), unique=True)  # Unique login key
    is_active = db.Column(db.Boolean, default=True)
    campaigns = db.relationship('Email', backref='user', lazy=True)

    def generate_login_key(self):
        self.login_key = secrets.token_hex(32)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    opened = db.Column(db.Boolean, default=False)
    opened_at = db.Column(db.DateTime)
    clicks = db.relationship('Click', backref='email', lazy=True)

class Click(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=False)
    url = db.Column(db.String(500))
    clicked_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
