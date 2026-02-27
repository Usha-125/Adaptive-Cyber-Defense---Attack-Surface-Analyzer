import os

class Config:
    # In production, set SECRET_KEY via environment variable or config management
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Rate limiting defaults
    RATELIMIT_DEFAULT = '10 per minute'
    RATELIMIT_STORAGE_URI = 'memory://'
    # Logging
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/security.log')