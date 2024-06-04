from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '1111'  # Change this to a random secret key

def init_db():
    conn = sqlite3.connect('pharmac.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS medicines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            medicine TEXT NOT NULL,
            quantity INTEGER NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    hashed_password = generate_password_hash('admin')
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
    ''', ('admin', hashed_password))  # Default admin user (change the password for security)
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You need to be logged in to view this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('pharmac.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    query = request.args.get('query')
    conn = sqlite3.connect('pharmac.db')
    cursor = conn.cursor()
    if query:
        cursor.execute('SELECT * FROM medicines WHERE name LIKE ?', ('%' + query + '%',))
    else:
        cursor.execute('SELECT * FROM medicines')
    medicines = cursor.fetchall()
    conn.close()
    return render_template('index.html', medicines=medicines)
@app.route('/order', methods=['GET', 'POST'])
@login_required
def order_medicine():
    if request.method == 'POST':
        name = request.form['name']
        medicine = request.form['medicine']
        quantity = request.form['quantity']

        conn = sqlite3.connect('pharmac.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO medicines (name, medicine, quantity)
            VALUES (?, ?, ?)
        ''', (name, medicine, quantity))
        conn.commit()
        conn.close()

        flash('Order placed successfully.')
        return render_template('order_medicine.html')  # Render the same page with success message

    return render_template('order_medicine.html')


@app.route('/delete/<int:medicine_id>')
@login_required
def delete_medicine(medicine_id):
    conn = sqlite3.connect('pharmac.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM medicines WHERE id = ?', (medicine_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/details/<int:medicine_id>')
@login_required
def details(medicine_id):
    conn = sqlite3.connect('pharmac.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM medicines WHERE id = ?', (medicine_id,))
    medicine = cursor.fetchone()
    conn.close()
    return render_template('details.html', medicine=medicine)

@app.route('/view_orders')
@login_required
def view_orders():
    conn = sqlite3.connect('pharmac.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM medicines')
    medicines = cursor.fetchall()
    conn.close()
    return render_template('view_orders.html', medicines=medicines)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    medicines = []
    query = ''
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        conn = sqlite3.connect('pharmac.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM medicines WHERE medicine LIKE ?', ('%' + query + '%',))
        medicines = cursor.fetchall()
        conn.close()
    return render_template('search.html', medicines=medicines, query=query)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        conn = sqlite3.connect('pharmac.db')
        cursor = conn.cursor()
        hashed_password = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
        conn.commit()
        conn.close()
        flash('Password reset successfully. Please login with your new password.')
        print("Password reset successful")  # Debug print
        return redirect(url_for('login'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
