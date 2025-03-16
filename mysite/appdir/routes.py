# File: routes.py

# Need to switch all tuples of single values to have a comma at the end...

import sys
from flask import render_template, session, redirect, url_for, flash, request
from flask_socketio import emit
from appdir import app, socketio
import pymysql
import hashlib
import string
import random
from datetime import datetime

random.seed()

# sys.path.append("mysite/appdir") # PYTHONANYWHERE (Remove this?)
sys.path.append("appdir") # LOCAL

from pymysql_lib import *

ERR_MSG = "An error occurred, please contact system admins."

# probably switch this to use the logging library
def handle_error(msg = ERR_MSG):
    flash(msg)
    error = db_error
    db_error = None
    # LOG ERROR HERE

# Index will be the global chatroom
@app.route('/')
@app.route('/index')
def index(data = None):
    if 'user_id' not in session: # not logged in
        return redirect(url_for('login'))

    # Collect the chat id from the request args
    chat_id = request.args.get('chat_id', default=1, type=int)
    
    conn, cur = db_connect()
    if conn is None:
        handle_error()
        ret = []
        chat_label = ""
        chatrooms = []
        
    else:
        # Set the current session chat id to either the chat trying to be accessed
        # or the global chat id if there is not a chat id
        session['chat_id'] = 1 if data is None else data['chat_id']
        
        # Make sure they are allowed to be in this chatroom.
        # Dont bother for global chat though, but redirect the user
        # to the global chat if they are not allowed in this chatroom.
        if chat_id != 1:
            cur.execute("SELECT * FROM chat_users WHERE chat_id = %s AND user_id = %s",
                        (chat_id, session['user_id']))
            # If they do not have permission to be in that chatroom, redirect to global chat.
            if cur.fetchone() is None:
                flash("Error: You do not have permission to access that chatroom.")
                chat_id = 1

        session['chat_id'] = chat_id
                
        # Fetch all chatrooms that the user has access to (and grab global because
        # everyone has it).
        cur.execute(
        """
        SELECT chats.id, chats.label
        FROM chats
        LEFT JOIN chat_users ON chats.id = chat_users.chat_id
        WHERE chats.id = 1 OR chat_users.user_id = %s
        """,
        (session['user_id'],)
        )

        # SORT THEM BY CHAT_ID LATER
        chatrooms = cur.fetchall()
                
        # Fetch the label of the current chatroom (i.e. the name for display)
        cur.execute("SELECT label FROM chats WHERE id = %s", (session['chat_id'],))
        label = cur.fetchone()['label']
        
        # Fetch all messages in chatroom
        cur.execute(
            '''
            SELECT u.username, m.message, m.time_sent, c.label FROM
            messages m
            JOIN users u ON m.user_id = u.id
            JOIN chats c ON m.chat_id = %s
            ORDER BY m.time_sent;
            ''',
            (session['chat_id'],)
        )
        ret = cur.fetchall()
        cur.close()
        conn.close()
                
    return render_template('index.html',
                           username = (session['username'] if 'username' in session else ''),
                           user_id = (session['user_id'] if 'user_id' in session else -1),
                           messages = ret,
                           chat_label = label,
                           chat_id = (session['chat_id'] if 'chat_id' in session else -1),
                           chatrooms = chatrooms)


@socketio.on('send_message')
def handle_message_send(data):
    if 'user_id' not in session:
        return

    user_id = session['user_id']
    username = session['username']
    message = data['message']
    chat_id = data['chat_id']

    conn, cur = db_connect()
    if conn is None:
        handle_error()
    else:
        cur.execute("INSERT INTO messages (user_id, chat_id, message) VALUES (%s, %s, %s)",
                    (user_id, chat_id, message))
        conn.commit()

        cur.execute("SELECT time_sent FROM messages WHERE user_id=%s AND chat_id=%s ORDER BY time_sent DESC LIMIT 1",
                    (user_id, chat_id))
        res = cur.fetchone()
        cur.close()
        conn.close()

        # Have to format it due to JSON serialization issues with
        # the javascript
        time_sent = res['time_sent'].strftime("%Y-%m-%d %H:%M:%S")
        
        # Broadcast the message to connected users
        emit('receive_message',
             {'username': username,
              'message': message,
              'time_sent': time_sent
             },
             broadcast=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # logged in users need to log out, send them to index.
    if 'user_id' in session:
        flash("You must log out before logging in.")
        return redirect(url_for('index'))

    # Prompt user to log in.
    if request.method == 'GET':
        return render_template('login.html',
                               user_id = (session['user_id'] if 'user_id' in session else -1),
                               username = (session['username'] if 'username' in session else ''))

    # Verify login attempt
    else:
        username = request.form['username']
        password = request.form['password']

        # Open database and request information
        conn, cur = db_connect()
        if conn is None:
            handle_error()
            return redirect(url_for('login'))

        cur.execute('SELECT salt FROM users WHERE username=%s', (username))
        ret = cur.fetchone()
        cur.close()
        conn.close()

        # If there is no row with that name, redirect to login to try again.
        if ret is None:
            flash('Unrecognized username.')
            return redirect(url_for('login'))

        # Append salt to the password
        password += ret['salt']
        # Hash
        for i in range(21):
            password = hashlib.sha256(password.encode()).hexdigest()
                
        # Verify
        conn, cur = db_connect()
        if conn is None:
            handle_error()
            redirect(url_for('login'))

        # Error checking here?
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
                               user_id = (session['user_id'] if 'user_id' in session else -1),
                               username = (session['username'] if 'username' in session else ''))

    else:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Open database and request information
        conn, cur = db_connect()
        if conn is None:
            handle_error()
            return redirect(url_for('register'))
        
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
        conn, cur = db_connect()
        if conn is None:
            handle_error()
            return redirect(url_for('register'))

        # Probably do error checking here too.
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
