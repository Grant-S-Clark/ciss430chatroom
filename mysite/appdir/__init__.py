# File: __init__.py

from flask import Flask
app = Flask(__name__)
app.secret_key = "SECRETKEYTEMPORARYSTRING"
from appdir import routes
