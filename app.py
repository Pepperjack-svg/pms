from flask import Flask, render_template, request, redirect, url_for, session, flash
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key' 
def read_users():
    try:
        with open('users.txt', 'r') as file:
            lines = file.readlines()
            users = [line.strip().split(':') for line in lines]
            return {username: password for username, password in users}
    except FileNotFoundError:
        return {}

def write_user(username, password):
    with open('users.txt', 'a') as file:
        file.write(f'{username}:{password}\n')

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    users = read_users()

    if username in users and sha256_crypt.verify(password, users[username]):
        session['user_id'] = username
        flash('Login successful', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password', 'danger')
        return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = read_users()

        if username in users:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        hashed_password = sha256_crypt.hash(password)
        write_user(username, hashed_password)

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    # Fetch parking spaces or any other data for the dashboard
    return render_template('dashboard.html', username=session['user_id'])

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
