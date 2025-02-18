# File: routes.py

import sys
from flask import render_template, session, redirect, url_for, flash, request
from appdir import app
import pymysql
import hashlib
import string
import random
random.seed()

sys.path.append("appdir")
from constants import *

@app.route('/')
@app.route('/index')
def index():
    if 'user_id' not in session: # not logged in
        return redirect(url_for('login'))
    else:
        return render_template('index.html',
                               user = (session['user_id'] if 'user_id' in session else -1),
                               username = (session['username'] if 'username' in session else ''))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # logged in users need to log out, send them to index.
    if 'user_id' in session:
        flash("You must log out before logging in.")
        return redirect(url_for('index'))

    # Prompt user to log in.
    if request.method == 'GET':
        return render_template('login.html',
                               user = (session['user_id'] if 'user_id' in session else -1),
                               username = (session['username'] if 'username' in session else ''))

    # Verify login attempt
    else:
        username = request.form['username']
        password = request.form['password']

        print("ATTEMPTING DATABASE")
        # Open database and request information
        conn = pymysql.connect(user=PYMYSQL_USER,
                               passwd=PYMYSQL_PASS,
                               db=DB_NAME,
                               host=DB_HOST)
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute('SELECT salt FROM users WHERE username=%s', (username))
        ret = cur.fetchone()
        cur.close()
        conn.close()

        # If there is no row with that name, redirect to login to
        # try again.
        if ret is None:
            print("USERNAME FAILURE")
            flash('Unrecognized username.')
            return redirect(url_for('login'))

        # Append salt to the password
        password += ret['salt']
        # Hash
        for i in range(21):
            password = hashlib.sha256(password.encode()).hexdigest()

        # Verify
        conn = pymysql.connect(user=PYMYSQL_USER,
                               passwd=PYMYSQL_PASS,
                               db=DB_NAME,
                               host=DB_HOST)
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute('SELECT id, username, hpassword FROM users WHERE username=%s', (username))
        ret = cur.fetchone()
        cur.close()
        conn.close()

        # Password matches
        if password == ret['hpassword']:
            session['user_id'] = ret['id']
            session['username'] = ret['username']
            return redirect(url_for('index'))
        
        # Password failed to match
        else:
            flash('Incorrect password.')
            return redirect(url_for('login'))
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        flash("You must log out before registering an account.")
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('register.html',
                               user = (session['user_id'] if 'user_id' in session else -1),
                               username = (session['username'] if 'username' in session else ''))

    else:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Open database and request information
        conn = pymysql.connect(user=PYMYSQL_USER,
                               passwd=PYMYSQL_PASS,
                               db=DB_NAME,
                               host=DB_HOST)
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute('SELECT id FROM users WHERE username=%s', (username))
        ret = cur.fetchone()
        cur.close()
        conn.close()
        
        # Username already exists, redirect to register.
        # Maybe also check for email too.
        if ret is not None:
            flash('Username already in use.')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for('register'))

        # Later also do password strength and disallow spaces and such...

        s = string.ascii_letters + string.digits + string.punctuation
        salt = ""
        for i in range(24): # salt is 24 characters exactly
            salt += random.choice(s)

        # Append salt to password
        password += salt
        # Hash
        for i in range(21):
            password = hashlib.sha256(password.encode()).hexdigest()
            
        # Open database to insert data
        conn = pymysql.connect(user=PYMYSQL_USER,
                               passwd=PYMYSQL_PASS,
                               db=DB_NAME,
                               host=DB_HOST)
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute('INSERT users (email, username, salt, hpassword) VALUES (%s, %s, %s, %s)',
                    (email, username, salt, password))
        conn.commit()
        cur.execute('SELECT id FROM users WHERE username=%s', (username)) # get id to log in.
        ret = cur.fetchone()
        cur.close()
        conn.close()

        session['user_id'] = ret['id']
        session['username'] = username
        
        flash("Registration successful")
        return redirect(url_for('index'))
    
@app.route('/logout')
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
    return redirect(url_for('login'))
