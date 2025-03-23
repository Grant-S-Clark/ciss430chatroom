# File: routes.py

# Need to switch all tuples of single values to have a comma at the end...

import sys
from flask import render_template, session, redirect, url_for, flash, request
from flask_socketio import emit, join_room, leave_room
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

# Index will be where users access chatrooms
@app.route('/')
@app.route('/index')
def index(data = None):
    if 'user_id' not in session: # not logged in
        return redirect(url_for('login'))

    # Collect the chat id from the request args
    session['chat_id'] = request.args.get('chat_id', default=1, type=int)
    if session['chat_id'] is None:
        session['chat_id'] = 1 if data is None else data['chat_id']
    
    conn, cur = db_connect()
    if conn is None:
        handle_error()
        ret = []
        chat_label = ""
        chat_type = ""
        is_owner = False
        gc_members = []
        chatrooms = []
        
    else:
        # Make sure they are allowed to be in this chatroom.
        # Dont bother for global chat though, but redirect the user
        # to the global chat if they are not allowed in this chatroom.
        if session['chat_id'] != 1:
            cur.execute("SELECT * FROM chat_users WHERE chat_id = %s AND user_id = %s",
                        (session['chat_id'], session['user_id']))
            # If they do not have permission to be in that chatroom, redirect to global chat.
            if cur.fetchone() is None:
                flash("Error: You do not have permission to access that chatroom.")
                session['chat_id'] = 1

        cur.execute("SELECT chat_type FROM chats WHERE id = %s", (session['chat_id'],))
        chat_type = cur.fetchone()['chat_type']

        # Grab group chat information
        if chat_type == "GROUP":
            cur.execute("SELECT * FROM group_chat_owners WHERE chat_id = %s AND user_id = %s",
                        (session['chat_id'], session['user_id']))
            if cur.fetchone() is None:
                is_owner = False
            else:
                is_owner = True

            cur.execute("""
            SELECT username FROM users
            JOIN chat_users ON user_id = users.id AND chat_id = %s
            """,
            (session['chat_id'],)
            )
            gc_members = cur.fetchall()
        else:
            is_owner = False
            gc_members = []
                
        # Fetch all chatrooms that the user has access to (and grab global because
        # everyone has it).
        cur.execute(
        """
        SELECT chats.id, chats.label, chats.chat_type
        FROM chats
        LEFT JOIN chat_users ON chats.id = chat_users.chat_id
        WHERE chats.id = 1 OR chat_users.user_id = %s
        ORDER BY chats.id
        """,
        (session['user_id'],)
        )
        chatrooms = cur.fetchall()
        label = None

        # Dynamically determine direct message chat labels
        for chat in chatrooms:
            if chat['chat_type'] == 'DM':
                cur.execute(
                    """
                    SELECT username FROM users WHERE id =
                    (SELECT user_id FROM chat_users WHERE chat_id = %s AND user_id != %s)
                    """,
                    (chat['id'], session['user_id'])
                )
                chat['label'] = cur.fetchone()['username']
                if chat['id'] == session['chat_id']:
                    label = chat['label']
                
        # Fetch the label of the current chatroom (i.e. the name for display)
        # if it is not already set
        if label is None:
            cur.execute("SELECT label FROM chats WHERE id = %s", (session['chat_id'],))
            label = cur.fetchone()['label']
        
        # Fetch all messages in chatroom
        cur.execute(
            '''
            SELECT u.username, m.message, m.time_sent, c.label FROM
            messages m
            JOIN users u ON u.id = m.user_id
            JOIN chats c ON c.id = %s AND m.chat_id = %s
            ORDER BY m.time_sent;
            ''',
            (session['chat_id'], session['chat_id'])
        )
        ret = cur.fetchall()
        cur.close()
        conn.close()
                
    return render_template('index.html',
                           username = (session['username'] if 'username' in session else ''),
                           user_id = session['user_id'],
                           messages = ret,
                           chat_label = label,
                           chat_id = session['chat_id'],
                           chat_type = chat_type,
                           is_owner = is_owner,
                           gc_members = gc_members,
                           chatrooms = chatrooms)


@socketio.on('send_message')
def handle_message_send(data):
    if 'user_id' not in session:
        return

    user_id = session['user_id']
    username = session['username']
    message = data['message']
    chat_id = session['chat_id']

    conn, cur = db_connect()
    if conn is None:
        handle_error()
    else:
        # Check to make sure you can send a message to this chat.
        if chat_id != 1:
            cur.execute("SELECT * FROM chat_users WHERE chat_id = %s AND user_id = %s",
                        (chat_id, user_id))
            if cur.fetchone() is None:
                cur.close()
                conn.close()

                # This flash wont show up?
                flash("Error: You do not have permission to access that chatroom.")
            
                # Broadcast an error to redirect to global chat.
                emit('receive_message',
                     {'username': username,
                      'message': message,
                      'time_sent': '',
                      'error': True
                     },
                     room=request.sid) # Only send error to the sender's socket.
                return

        # Put message into the chatroom.
        cur.execute("INSERT INTO messages (user_id, chat_id, message) VALUES (%s, %s, %s)",
                    (user_id, chat_id, message))
        conn.commit()

        cur.execute("SELECT time_sent FROM messages WHERE user_id=%s AND chat_id=%s ORDER BY time_sent DESC LIMIT 1",
                    (user_id, chat_id))
        res = cur.fetchone()

        # Get list of recipients, this is to make sure users within a group chat that they
        # were just removed from will not get any messages delivered to them
        cur.execute("SELECT user_id FROM chat_users WHERE chat_id = %s", (chat_id,))
        user_ids = [ result['user_id'] for result in cur.fetchall() ]
        cur.close()
        conn.close()

        # Have to format it due to JSON serialization issues with
        # the javascript
        time_sent = res['time_sent'].strftime("%Y-%m-%d %H:%M:%S")
        
        # Broadcast the message to connected users
        emit('receive_message',
             {'username': username,
              'message': message,
              'time_sent': time_sent,
              'recipients': user_ids,
              'error': False
             },
             room=f"chat_{chat_id}")

    return

@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data.get("chat_id")
    if chat_id:
        join_room(f"chat_{chat_id}")

@socketio.on('leave_chat')
def handle_join_chat(data):
    chat_id = data.get("chat_id")
    if chat_id:
        leave_room(f"chat_{chat_id}")    
    
@app.route('/chat_type', methods=['GET'])
def chat_type():
    if 'user_id' not in session:
        flash('You must log in to access that page.')
        return redirect(url_for('login'))
    
    return render_template('chat_type.html',
                           user_id = session['user_id'])

@app.route('/new_dm', methods=['GET', 'POST'])
def new_dm():
    if 'user_id' not in session:
        flash('You must log in to access that page.')
        return redirect(url_for('login'))

    if request.method == "POST":
        selected_user_id = request.form.get("selected_user_id")
        if not selected_user_id:
            flash("Please selecte a user.")
            return redirect(url_for('new_dm'))
        
        selected_user_id = int(selected_user_id)

        conn, cur = db_connect()
        if conn is None:
            handle_error()
            flash("Something went wrong, please try again.")
            return redirect(url_for('new_dm'))

        else:
            # Ensure existence of user
            cur.execute("SELECT * FROM users WHERE id = %s", (selected_user_id,))
            if cur.fetchone() is None:
                cur.close()
                conn.close()
                flash("Could not find user. Please try again.")
                return redirect(url_for('new_dm'))

            # Make sure this DM does not already exist
            cur.execute("""
            SELECT * FROM chats
            JOIN chat_users cu1 ON chats.id = cu1.chat_id
            JOIN chat_users cu2 ON chats.id = cu2.chat_id
            WHERE chats.chat_type = 'DM'
            AND cu1.user_id = %s
            AND cu2.user_id = %s
            """,
            (session['user_id'], selected_user_id)
            )
            if cur.fetchone() is not None:
                cur.close()
                conn.close()
                flash("You already have a direct message open with this user.")
                return redirect(url_for('new_dm'))

            # Create the DM and redirect the user to it.
            cur.execute("INSERT chats (label, chat_type) VALUES (NULL, 'DM')")
            new_chat_id = cur.lastrowid
            cur.execute("""
            INSERT chat_users (chat_id, user_id) VALUES
            (%s, %s),
            (%s, %s)
            """,
            (new_chat_id, session['user_id'], new_chat_id, selected_user_id)
            )
            conn.commit()

            cur.close()
            conn.close()
            flash("Direct message created successfully.")
            return redirect(url_for("index", chat_id = new_chat_id))

    conn, cur = db_connect()
    if conn is None:
        handle_error()
        users = []
    else:
        cur.execute("SELECT id, username FROM users WHERE id != %s", (session['user_id'],))
        users = cur.fetchall()
        cur.close()
        conn.close()
        
    return render_template('new_dm.html',
                           user_id = session['user_id'],
                           users = users)

@app.route('/close_dm', methods=['POST'])
def close_dm():
    if 'user_id' not in session:
        flash('You must log in to access that page.')
        return redirect(url_for('login'))

    conn, cur = db_connect()
    if conn is None:
        handle_error()
        return redirect(url_for('index', chat_id = session['chat_id']))
    else:
        # Ensure this chat is a DM and you have access to it.
        cur.execute("SELECT * FROM chats WHERE id = %s AND chat_type = 'DM'",
                    (session['chat_id'],))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("Error encountered trying to delete direct message chatroom. Please try again later.")
            return redirect(url_for('index', chat_id = session['chat_id']))

        cur.execute("SELECT * FROM chat_users WHERE chat_id = %s AND user_id = %s",
                    (session['chat_id'], session['user_id']))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("Error encountered trying to delete DM. Please try again later.")
            return redirect(url_for('index', chat_id = session['chat_id']))

        # Delete the DM. Cascade deletes handle the rest.
        cur.execute("DELETE FROM chats WHERE id = %s", (session['chat_id'],))
        conn.commit()

        cur.close()
        conn.close()
        flash("Direct message chat deleted successfully.")
        
        # Kick everyone out by broadcasting an error to them all
        socketio.emit('receive_message',
                      {'username': '',
                       'message': '',
                       'time_sent': '',
                       'error': True
                      },
                      room=f"chat_{session['chat_id']}")

        # Redirect
        return redirect(url_for('index'))

@app.route('/new_gc', methods=['GET', 'POST'])
def new_gc():
    if 'user_id' not in session:
        flash('You must log in to access that page.')
        return redirect(url_for('login'))

    if request.method == "POST":
        group_name = request.form.get("group_name").strip()
        if group_name == "Global Chat":
            flash('You cannot make a chatroom named "Global Chat", please choose another name.')
            return redirect(url_for('new_gc'))
        
        user_ids = request.form.get("selected_users")
        if len(user_ids) == 0:
            user_ids = []
        else:
            user_ids = [ int(id_str) for id_str in user_ids.split(',') ]
            
        conn, cur = db_connect()
        if conn is None:
            handle_error()
            cur.close()
            conn.close()
            flash("Something went wrong, please try again.")
            return redirect(url_for('new_gc'))
        else:
            # Ensure all users exist
            for uid in user_ids:
                cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
                if cur.fetchone() is None:
                    cur.close()
                    conn.close()
                    flash("Could not find one or more users. Please try again.")
                    return redirect(url_for('new_gc'))

            # Create the DM and mark the current user ID as the owner.
            cur.execute("INSERT chats (label, chat_type) VALUES (%s, 'GROUP')", (group_name,))
            new_chat_id = cur.lastrowid
            cur.execute("INSERT chat_users (chat_id, user_id) VALUES (%s, %s)",
                        (new_chat_id, session['user_id']))
            cur.execute("INSERT group_chat_owners (chat_id, user_id) VALUES (%s, %s)",
                        (new_chat_id, session['user_id']))

            # Add other users into the chat.
            for uid in user_ids:
                cur.execute("INSERT chat_users (chat_id, user_id) VALUES (%s, %s)",
                            (new_chat_id, uid))

            conn.commit()

            cur.close()
            conn.close()

            flash("Group created successfully.")
            return redirect(url_for("index", chat_id = new_chat_id))
            
    conn, cur = db_connect()
    if conn is None:
        handle_error()
        users = []
    else:
        cur.execute("SELECT id, username FROM users WHERE id != %s", (session['user_id'],))
        users = cur.fetchall()
        cur.close()
        conn.close()
        
    return render_template('new_gc.html',
                           user_id = session['user_id'],
                           users = users)

# ADD USERS FUNCTION
@app.route('/add_gc_members', methods=['GET', 'POST'])
def add_gc_members():

    if request.method == 'POST':
        user_ids = request.form.get("selected_users")
        if len(user_ids) == 0:
            return redirect(url_for("index", chat_id = session['chat_id'])) # Nothing to do
        else:
            user_ids = [ int(id_str) for id_str in user_ids.split(',') ]
            
        conn, cur = db_connect()
        if conn is None:
            handle_error()
            users = []
        else:
            # Assure this is the chatroom owner
            cur.execute("SELECT * FROM group_chat_owners WHERE chat_id = %s AND user_id = %s",
                        (session['chat_id'], session['user_id']))
            if cur.fetchone() is None:
                cur.close()
                conn.close()
                flash("You do not have permission to visit that page.")
                return redirect(url_for("index", chat_id = session['chat_id']))

            # Ensure all users exist
            for uid in user_ids:
                cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
                if cur.fetchone() is None:
                    cur.close()
                    conn.close()
                    flash("Could not find one or more users. Please try again.")
                    return redirect(url_for('add_gc_members'))
                
            # Add users into the chat.
            for uid in user_ids:
                cur.execute("INSERT chat_users (chat_id, user_id) VALUES (%s, %s)",
                            (session['chat_id'], uid))

            conn.commit()

            cur.close()
            conn.close()

            flash("Members added successfully.")
            return redirect(url_for("index", chat_id = session['chat_id']))
        
    conn, cur = db_connect()
    if conn is None:
        handle_error()
        users = []
    else:
        # Assure this is the chatroom owner
        cur.execute("SELECT * FROM group_chat_owners WHERE chat_id = %s AND user_id = %s",
                    (session['chat_id'], session['user_id']))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("You do not have permission to visit that page.")
            return redirect(url_for("index", chat_id = session['chat_id']))
        
        # Get all users not in this chatroom
        cur.execute(
        """
        SELECT id, username FROM users
        WHERE id NOT IN (SELECT user_id FROM chat_users WHERE chat_id = %s)
        """,
        (session['chat_id'],))
        users = cur.fetchall()
        cur.close()
        conn.close()
        
    return render_template('add_gc_members.html',
                           user_id = session['user_id'],
                           users = users)

@app.route('/remove_gc_members', methods=['GET', 'POST'])
def remove_gc_members():

    if request.method == 'POST':
        user_ids = request.form.get("selected_users")
        if len(user_ids) == 0:
            return redirect(url_for("index", chat_id = session['chat_id'])) # Nothing to do
        else:
            user_ids = [ int(id_str) for id_str in user_ids.split(',') ]
            
        conn, cur = db_connect()
        if conn is None:
            handle_error()
            users = []
        else:
            # Assure this is the chatroom owner
            cur.execute("SELECT * FROM group_chat_owners WHERE chat_id = %s AND user_id = %s",
                        (session['chat_id'], session['user_id']))
            if cur.fetchone() is None:
                cur.close()
                conn.close()
                flash("You do not have permission to visit that page.")
                return redirect(url_for("index", chat_id = session['chat_id']))

            # Ensure all users exist
            for uid in user_ids:
                cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
                if cur.fetchone() is None:
                    cur.close()
                    conn.close()
                    flash("Could not find one or more users. Please try again.")
                    return redirect(url_for('add_gc_members'))
                
            # Remove users from the chatroom
            for uid in user_ids:
                cur.execute("DELETE FROM chat_users WHERE chat_id = %s AND user_id = %s",
                            (session['chat_id'], uid))

            conn.commit()

            cur.close()
            conn.close()
            
            # Kick the members out of the chatroom if they are in it.
            for uid in user_ids:
                socketio.emit("removed_from_group",
                              {'chat_id' : session['chat_id']},
                              room=f"user_{uid}")
                print("BROADCASTED ON", f"user_{uid}")
                
            flash("Members removed successfully.")
            return redirect(url_for("index", chat_id = session['chat_id']))
        
    conn, cur = db_connect()
    if conn is None:
        handle_error()
        users = []
    else:
        # Assure this is the chatroom owner
        cur.execute("SELECT * FROM group_chat_owners WHERE chat_id = %s AND user_id = %s",
                    (session['chat_id'], session['user_id']))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("You do not have permission to visit that page.")
            return redirect(url_for("index", chat_id = session['chat_id']))
        
        # Get all users in the chatroom
        cur.execute(
        """
        SELECT id, username FROM users
        WHERE id IN (SELECT user_id FROM chat_users WHERE chat_id = %s AND user_id != %s)
        """,
        (session['chat_id'], session['user_id']))
        users = cur.fetchall()
        cur.close()
        conn.close()
        
    return render_template('remove_gc_members.html',
                           user_id = session['user_id'],
                           users = users)

@app.route('/leave_gc', methods=['POST'])
def leave_gc():
    if 'user_id' not in session:
        flash('You must log in to access that page.')
        return redirect(url_for('login'))

    conn, cur = db_connect()
    if conn is None:
        handle_error()
        return redirect(url_for('index', chat_id = session['chat_id']))
    else:
        # Ensure this chat is a group chat and you have access to it.
        cur.execute("SELECT * FROM chats WHERE id = %s AND chat_type = 'GROUP'",
                    (session['chat_id'],))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("Error encountered trying to leave group message chatroom. Please try again later.")
            return redirect(url_for('index', chat_id = session['chat_id']))

        cur.execute("SELECT * FROM chat_users WHERE chat_id = %s AND user_id = %s",
                    (session['chat_id'], session['user_id']))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("Error encountered trying to leave group message chatroom. Please try again later.")
            return redirect(url_for('index', chat_id = session['chat_id']))

        # Handle ownership transfer
        cur.execute("SELECT * FROM group_chat_owners WHERE chat_id = %s AND user_id = %s",
                    (session['chat_id'], session['user_id']))
        if cur.fetchone() is not None:
            cur.execute("""
            SELECT u.id FROM users AS u
            JOIN chat_users AS cu ON cu.user_id = u.id AND cu.chat_id = %s
            WHERE u.id != %s
            ORDER BY cu.time_joined LIMIT 1
            """,
            (session['chat_id'], session['user_id']))
            next_owner = cur.fetchone()
            if next_owner is None:
                cur.close()
                conn.close()
                flash("Cannot leave chat as last member. You must delete this chat.")
                return redirect(url_for('index', chat_id = session['chat_id']))

            cur.execute("UPDATE group_chat_owners SET user_id = %s WHERE chat_id = %s",
                        (next_owner['id'], session['chat_id']))
            
        # Remove session's user_id from the chat's access permissions.
        cur.execute("DELETE FROM chat_users WHERE chat_id = %s AND user_id = %s",
                    (session['chat_id'], session['user_id']))
        conn.commit()

        cur.close()
        conn.close()
        flash("Left group successfully.")

        # Redirect self to global chat
        return redirect(url_for('index'))

@app.route('/close_gc', methods=['POST'])
def close_gc():
    if 'user_id' not in session:
        flash('You must log in to access that page.')
        return redirect(url_for('login'))

    conn, cur = db_connect()
    if conn is None:
        handle_error()
        return redirect(url_for('index', chat_id = session['chat_id']))
    else:
        # Ensure this chat is a group chat and you have access to it.
        cur.execute("SELECT * FROM chats WHERE id = %s AND chat_type = 'GROUP'",
                    (session['chat_id'],))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("Error encountered trying to delete group message chatroom. Please try again later.")
            return redirect(url_for('index', chat_id = session['chat_id']))

        cur.execute("SELECT * FROM chat_users WHERE chat_id = %s AND user_id = %s",
                    (session['chat_id'], session['user_id']))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("Error encountered trying to delete group message chatroom. Please try again later.")
            return redirect(url_for('index', chat_id = session['chat_id']))

        # Ensure you are the group owner and can delete it.
        cur.execute("SELECT * FROM group_chat_owners WHERE chat_id = %s AND user_id = %s",
                    (session['chat_id'], session['user_id']))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            flash("Error encountered trying to delete group message chatroom. Please try again later.")
            return redirect(url_for('index', chat_id = session['chat_id']))

        # Delete the group chat. Cascade deletes handle the rest.
        cur.execute("DELETE FROM chats WHERE id = %s", (session['chat_id'],))
        conn.commit()

        cur.close()
        conn.close()
        flash("Group chat deleted successfully.")
        
        # Kick everyone out by broadcasting an error to them all
        socketio.emit('receive_message',
                      {'username': '',
                       'message': '',
                       'time_sent': '',
                       'error': True
                      },
                      room=f"chat_{session['chat_id']}")

        # Redirect
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # logged in users need to log out, send them to index.
    if 'user_id' in session:
        flash("You must log out before logging in.")
        return redirect(url_for('index'))

    # Prompt user to log in.
    if request.method == 'GET':
        return render_template('login.html', user_id = -1)

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
        return render_template('register.html', user_id = -1)

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
        
        flash("Registration successful")
        return redirect(url_for('login'))
    
@app.route('/logout')
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
    return redirect(url_for('login'))
