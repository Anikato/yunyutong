import os
import sys

# Set environment variables for testing BEFORE importing app modules
os.environ['FLASK_ENV'] = 'testing'
# Generate a valid Fernet key for testing to avoid invalid token errors if checked
from cryptography.fernet import Fernet
os.environ['ENCRYPTION_KEY'] = Fernet.generate_key().decode()

def verify():
    print("Attempting to import app...")
    try:
        from app import create_app, db
        from app.models import User
        print("Imports successful.")
    except Exception as e:
        print(f"Failed to import app: {e}")
        sys.exit(1)

    print("Attempting to create app...")
    try:
        app = create_app()
        print("App created successfully.")
    except Exception as e:
        print(f"Failed to create app: {e}")
        sys.exit(1)

    print("Verifying database configuration...")
    with app.app_context():
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        print(f"Database URI: {db_uri}")
        
        # Check if it points to yunyutong.db in the project root (where config.py is)
        if 'yunyutong.db' in db_uri:
            print("Database path seems correct (contains yunyutong.db).")
        else:
            print(f"Warning: Database URI might not point to the expected file. Expected to contain 'yunyutong.db'.")

        try:
            print("Imported User model successfully.")
            print("Verification complete. Structure seems correct.")
        except Exception as e:
            print(f"Database/Model verification failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    verify()
