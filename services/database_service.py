# services/database_service.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config.connection import DATABASE_CONFIG

try:
    engine = create_engine(f"mysql+mysqldb://{DATABASE_CONFIG['user']}:{DATABASE_CONFIG['password']}@{DATABASE_CONFIG['host']}/{DATABASE_CONFIG['database']}")
    Session = sessionmaker(bind=engine)
    session = Session()
    print("MySQL connection successful (SQLAlchemy)")
except Exception as e:
    print(f"MySQL connection error (SQLAlchemy): {e}")
    engine = None
    session = None
