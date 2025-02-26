# File: __init__.py

from flask import Flask
from flask_socketio import SocketIO

# HOW TO GET FLASK SOCKETS TO WORK:
# pip uninstall flask-socketio python-socketio python-engineio -y
# pip install flask-socketio==5.3.6 python-socketio==5.8.0 python-engineio==4.3.1

app = Flask(__name__)
app.secret_key = "SECRETKEYTEMPORARYSTRING"
socketio = SocketIO(app, cors_allowed_origins="*")

from appdir import routes
