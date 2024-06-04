import sqlite3
from werkzeug.security import generate_password_hash

def add_user(username, password):
    conn = sqlite3.connect('pharmac.db')
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    cursor.execute('''
        INSERT INTO users (username, password) VALUES (?, ?)
    ''', (username, hashed_password))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    username = input("Enter username: ")
    password = input("Enter password: ")
    add_user(username, password)
