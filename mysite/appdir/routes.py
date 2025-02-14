# File: routes.py

from flask import render_template
from appdir import app

@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html", user="<USERNAME>")
