from scheduler import app, db, auth
from flask import render_template, request, session, redirect, url_for, abort, flash
from bson.objectid import ObjectId

@app.route('/auth', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        confirmation = request.form['confirmation']
        if password != confirmation:
            flash('Введённые пароли не совпадают', 'warning')
            return render_template('signup.html', title='Регистрация')
        if db.users.find_one({'username':username}) is not None:
            flash('Введённый логин уже зарегестрирован', 'danger')
            return render_template('signup.html', title='Регистрация')

        salt = auth.gen_salt()
        salted_password = auth.hash_password_and_salt(password, salt)
        inserted_user = db.users.insert_one({
            'username': username,
            'password': salted_password,
            'salt': salt,
            'invited_to': [],
            'subscribed_to': [],
            'firebase_id': ''
        })
        user_id = str(inserted_user.inserted_id)
        session['token'] = auth.gen_signed_token(user_id)
        return redirect(url_for('home'))
    return render_template('signup.html', title='Регистрация')

@app.route('/register', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']

        user = db.users.find_one({'username': username})
        if user is None:
            flash('Неверный логин или пароль', 'danger')
            return render_template('signin.html', title='Авторизация')

        salt = user['salt']
        if not auth.check_password(password, salt, user['password']):
            flash('Неверный логин или пароль', 'danger')
            return render_template('signin.html', title='Авторизация')
        user_id = str(user['_id'])
        session['token'] = auth.gen_signed_token(user_id)
        return redirect(url_for('home'))
    return render_template('signin.html', title='Авторизация')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/')
def home():
    if 'token' in session:
        user_id = auth.check_token(session['token'])
        if user_id is not None:
            user = db.users.find_one({'_id': ObjectId(user_id)})
            schedules = db.schedules.find({'_id': {'$in': user['subscribed_to']}}, {'name': 1, 'alias': 1})
            return render_template('main.html', user=user, schedules=schedules)
    return render_template('main.html')

@app.route('/schedules/<alias>')
def view_schedule(alias):
    return alias

@app.route('/schedules/create')
def create_schedule():
    return render_template('')
