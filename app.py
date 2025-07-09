from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from influxdb import InfluxDBClient
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Initialize SQLite database ---
def init_user_db():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )''')
        conn.commit()

init_user_db()

# --- Connect to InfluxDB ---
influx_client = InfluxDBClient(host='localhost', port=8086)
influx_client.switch_database('microclimate')

# --- Login required decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first.', 'warning')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# --- Home route ---
@app.route('/')
def home():
    return redirect('/login')

# --- Login route ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['role'] = user[3]
            flash('Login successful!', 'success')
            return redirect('/admin-dashboard' if user[3] == 'admin' else '/dashboard')
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

# --- Register route ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')

        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = c.fetchone()

            if existing_user:
                flash('Username already exists!', 'error')
                return redirect('/register')

            password_hash = generate_password_hash(password)
            try:
                c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                          (username, password_hash, role))
                conn.commit()
                session['username'] = username
                session['role'] = role
                flash('Registration successful! Welcome.', 'success')
                return redirect('/admin-dashboard' if role == 'admin' else '/dashboard')
            except sqlite3.Error as e:
                flash(f'Database error: {e}', 'error')

    return render_template('register.html')

# --- User dashboard ---
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# --- Admin dashboard ---
@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if session.get('role') != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect('/dashboard')

    try:
        results = influx_client.query('''
            SELECT LAST("temperature") AS temperature,
                   LAST("humidity") AS humidity,
                   LAST("light") AS light,
                   LAST("soil") AS soil,
                   LAST("wind_velocity") AS wind_velocity,
                   LAST("wind_direction") AS wind_direction
            FROM sensor_data
        ''')
        points = list(results.get_points())
        latest = points[0] if points else {
            'temperature': 0,
            'humidity': 0,
            'light': 0,
            'soil': 0,
            'wind_velocity': 0,
            'wind_direction': 0
        }

        labels = ["12:00", "12:05", "12:10", "12:15", "12:20"]
        data = {
            'labels': labels,
            'temperature': [latest.get('temperature', 0)] * 5,
            'humidity': [latest.get('humidity', 0)] * 5,
            'light': [latest.get('light', 0)] * 5,
            'soil': [latest.get('soil', 0)] * 5,
            'wind_velocity': [latest.get('wind_velocity', 0)] * 5,
            'wind_direction': [latest.get('wind_direction', 0)] * 5
        }

        return render_template('dashboard2.html', **data)

    except Exception as e:
        flash(f"Error fetching sensor data: {str(e)}", 'error')
        return render_template('dashboard2.html',
                               labels=["Error"] * 5,
                               temperature=[0] * 5,
                               humidity=[0] * 5,
                               light=[0] * 5,
                               soil=[0] * 5,
                               wind_velocity=[0] * 5,
                               wind_direction=[0] * 5)

# --- Logout route ---
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/login')

# --- Run app ---
if __name__ == '__main__':
    app.run(debug=True)
