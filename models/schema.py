# models.py
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from services.database_service import engine
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime


Base = declarative_base() # creates a base class for declarative class definitions in SQLAlchemy, enabling you to define database tables as Python classes.

class User(Base): # defines the table schema for the table 'users'.
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True) # serves as the uniques record identifier.
    email = Column(String(100), unique=True, nullable=False) # column to store the email.
    password_hash=Column(String(100),nullable=False) # to store the password in hashed form.
    created_at = Column(DateTime, default=datetime.utcnow) # column that stores the time and date of user creaion.

Base.metadata.create_all(engine) # creates all the database tables defined as SQLAlchemy models associated with the Base metadata, using the provided database engine.
