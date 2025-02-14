# File: flask_app.py

from appdir import app

app.jinja_env.auto_reload = True
app.config['DEBUG'] = True
app.config['TEMPLATES_AUTO_RELOAD'] = True

