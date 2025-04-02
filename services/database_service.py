# services/database_service.py
import mysql.connector
from config.connection import DATABASE_CONFIG

try:
    db_connection = mysql.connector.connect(
        host=DATABASE_CONFIG["host"],
        user=DATABASE_CONFIG["user"],
        password=DATABASE_CONFIG["password"],
        database=DATABASE_CONFIG["database"]
    )
    db_cursor = db_connection.cursor(dictionary=True)
    print("MySQL connection successful")
except Exception as e:
    print(f"MySQL connection error: {e}")
    db_connection = None
    db_cursor = None