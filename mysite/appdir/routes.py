# File: routes.py

from flask import render_template, session
from appdir import app

@app.route('/')
@app.route('/index')
def index():
    if 'user' not in session:
        return render_template("login.html")
    else:
        return render_template("index.html", user=session['user'])

