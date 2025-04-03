from flask import Flask
from routes.routes import routes_bp
import os
import secrets
import random
from services.database_service import db_cursor, db_connection 

random.seed(42) # Ensures that the secret keys generated stay consistent
app=Flask(__name__) # Initialization of Flask App.
app.secret_key=secrets.token_hex(32) # Generate the secret key for the Flask App.
app.register_blueprint(routes_bp) # Integrates a modular set of routes and resources (a Blueprint) into a Flask application.


if __name__=="__main__":
    app.run(debug=True)


