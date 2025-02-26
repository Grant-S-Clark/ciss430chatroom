# File: flask_app.py

from appdir import app, socketio

app.jinja_env.auto_reload = True
app.config['DEBUG'] = True
app.config['TEMPLATES_AUTO_RELOAD'] = True

if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0")
