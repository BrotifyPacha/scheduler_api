from scheduler import app, db, auth
from flask import render_template, request, session, redirect, url_for, abort, flash
from pprint import pformat

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        confirmation = request.form['confirmation']
        if password != confirmation:
            flash('Введённые пароли не совпадают', 'warning')
            return render_template('register.html', title='Регистрация')
        if db.users.find_one({'username':username}) is not None:
            flash('Введённый логин уже зарегестрирован', 'danger')
            return render_template('register.html', title='Регистрация')

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
    return render_template('register.html', title='Регистрация')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']

        user = db.users.find_one({'username': username})
        if user is None:
            flash('Неверный логин или пароль', 'danger')
            return render_template('login.html', title='Авторизация')

        salt = user['salt']
        if not auth.check_password(password, salt, user['password']):
            flash('Неверный логин или пароль', 'danger')
            return render_template('login.html', title='Авторизация')
        user_id = str(user['_id'])
        session['token'] = auth.gen_signed_token(user_id)
        return redirect(url_for('home'))
    return render_template('login.html', title='Авторизация')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/')
def home():
    cred = auth.check_session_for_token(session)
    if bool(cred):
        print(pformat(cred))
        return render_template('main.html', user=cred['user'], schedules=cred['schedules'])
    return render_template('main.html')

@app.route('/schedules/<alias>')
def view_schedule(alias):
    return alias

@app.route('/schedules/create')
def create_schedule():
    cred = auth.check_session_for_token(session)
    if bool(cred):
        return render_template('create_schedule.html', title='Создание', user=cred['user'], schedules=cred['schedules'])
    else:
        flash('Вам нужно быть авторизованным, чтобы создать расписание', 'warning')
    return redirect(url_for('home'))