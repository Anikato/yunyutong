import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-replace-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'yunyutong.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    FLASK_ENV = os.environ.get('FLASK_ENV', 'production')
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', '0')
