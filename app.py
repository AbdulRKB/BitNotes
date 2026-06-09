import os
import sqlite3
import uuid
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from config import Config
import crypto_utils
import base64

app = Flask(__name__)
app.config.from_object(Config)
Session(app)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                encrypted_master_key BLOB NOT NULL,
                salt BLOB NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                encrypted_title BLOB NOT NULL,
                encrypted_content BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS active_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_id TEXT UNIQUE NOT NULL,
                user_agent TEXT NOT NULL,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()

init_db()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            try:
                master_key = crypto_utils.decrypt_master_key(user['encrypted_master_key'], password, user['salt'])
                
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['master_key'] = master_key
                
                session_id = str(uuid.uuid4())
                session['session_id'] = session_id
                user_agent = request.headers.get('User-Agent', 'Unknown')
                db.execute('INSERT INTO active_sessions (user_id, session_id, user_agent) VALUES (?, ?, ?)',
                           (user['id'], session_id, user_agent))
                db.commit()
                
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash('Login failed. Decryption error.')
        else:
            flash('Invalid email or password.')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            flash('Email already registered.')
        else:
            salt = crypto_utils.generate_salt()
            master_key = crypto_utils.generate_master_key()
            encrypted_master_key = crypto_utils.encrypt_master_key(master_key, password, salt)
            password_hash = generate_password_hash(password)
            
            db.execute('INSERT INTO users (email, password_hash, encrypted_master_key, salt) VALUES (?, ?, ?, ?)',
                       (email, password_hash, encrypted_master_key, salt))
            db.commit()
            
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    db = get_db()
    master_key = session.get('master_key')
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        encrypted_title = crypto_utils.encrypt_data(title, master_key)
        encrypted_content = crypto_utils.encrypt_data(content, master_key)
        
        db.execute('INSERT INTO notes (user_id, encrypted_title, encrypted_content) VALUES (?, ?, ?)',
                   (session['user_id'], encrypted_title, encrypted_content))
        db.commit()
        return redirect(url_for('dashboard'))
        
    notes_rows = db.execute('SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],)).fetchall()
    notes = []
    for row in notes_rows:
        try:
            title = crypto_utils.decrypt_data(row['encrypted_title'], master_key)
            content = crypto_utils.decrypt_data(row['encrypted_content'], master_key)
            notes.append({
                'id': row['id'],
                'title': title,
                'content': content,
                'created_at': row['created_at']
            })
        except Exception:
            notes.append({
                'id': row['id'],
                'title': 'Error decrypting note',
                'content': 'Unable to decrypt this note. Key mismatch.',
                'created_at': row['created_at']
            })
            
    return render_template('dashboard.html', notes=notes)

@app.route('/account')
@login_required
def account():
    db = get_db()
    sessions = db.execute('SELECT * FROM active_sessions WHERE user_id = ? ORDER BY login_time DESC', (session['user_id'],)).fetchall()

    content = ""

    for s in sessions:
        if s['session_id'] == session.get('session_id'):
            content += f"""
                        <tr>
                            <td class="session-time">{s['login_time']}</td>
                            <td class="session-agent">{s['user_agent']}</td>
                            <td>
                                    <span class="status-badge badge-active">Current Session</span>
                            </td>
                        </tr>
        """
        else:
            content += f"""
                        <tr>
                            <td class="session-time">{s['login_time']}</td>
                            <td class="session-agent">{s['user_agent']}</td>
                            <td>
                                    <span class="status-badge badge-inactive">Active</span>
                            </td>
                        </tr>
        """

    acc = """{% extends 'base.html' %}

{% block content %}
<div class="account-layout">
    <div class="account-container">
        <div class="account-header">
            <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" class="text-primary"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
            <h2>Account Settings</h2>
        </div>
        
        <div class="account-card">
            <div class="account-card-header">
                <h3>Active Sessions</h3>
                <p>Manage the devices that are currently logged into your BitNotes account.</p>
            </div>
            
            <div class="table-responsive">
                <table class="sessions-table">
                    <thead>
                        <tr>
                            <th style="width: 25%">Started</th>
                            <th style="width: 55%">Device / Browser</th>
                            <th style="width: 20%">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                    """+ content +"""
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
{% endblock %}
    """
    return render_template_string(acc, sessions=sessions, current_session_id=session.get('session_id'))

@app.route('/logout')
def logout():
    session_id = session.get('session_id')
    if session_id:
        db = get_db()
        db.execute('DELETE FROM active_sessions WHERE session_id = ?', (session_id,))
        db.commit()
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('flask_session', exist_ok=True)
    app.run(debug=True)
