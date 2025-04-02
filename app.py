from flask import Flask
from routes.routes import routes_bp
import os
import secrets
import random
from services.database_service import db_cursor, db_connection 

random.seed(42)
app=Flask(__name__)
app.secret_key=secrets.token_hex(32)
app.register_blueprint(routes_bp)


if __name__=="__main__":
    app.run(debug=True)


