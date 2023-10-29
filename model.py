from flask import app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    blocked_time = db.Column(db.DateTime, nullable=True)
    otp_secret = db.Column(db.String(120), unique=True, nullable=True)

