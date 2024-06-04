import sqlite3

def delete_user(username):
    conn = sqlite3.connect('pharmac.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    print(f'User {username} deleted successfully.')

if __name__ == '__main__':
    username = input('Enter username to delete: ')
    delete_user(username)
