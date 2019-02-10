from scheduler import app, db, auth
from flask import render_template, request, session, redirect, url_for, flash
from bson.objectid import ObjectId
from scheduler import utils
from ast import literal_eval
import re

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        confirmation = request.form['confirmation']

        if (len(username) < 1):
            flash('Логин должен иметь хотя бы один символ', 'danger')
            return render_template('register.html', title='Регистрация')

        if not re.match('[a-z0-9_.]+', username):
            flash('Разрешены лишь символы латиницы (a-z), арабские цифры (0-9), подчёркивание "_"  и точка "."', 'danger')
            return render_template('register.html', title='Регистрация')

        if re.match('.*__.*', username):
            flash('Между двумя символами "_" или "." должна быть хотябы одна буква или цифра', 'danger')
            return render_template('register.html', title='Регистрация')

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
    user_id = auth.check_session_for_token(session)
    if user_id is not None:
        user = db.users.find_one({'_id': ObjectId(user_id)})
        schedules = db.schedules.find({'subscribed_users': ObjectId(user_id)})
        return render_template('main.html', user=user, schedules=schedules)
    return render_template('main.html')

@app.route('/schedules/<alias>')
def view_schedule(alias):
    user_id = auth.check_session_for_token(session)

    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        flash('Расписания по данной ссылке не найдено', 'danger')
        return redirect(url_for('home'));

    if schedule['availability'] == 'private':
        if ObjectId(user_id) not in schedule['subscribed_users'] or ObjectId(user_id) != schedule['creator']:
            flash('У вас нет доступа к этому расписанию, если вы считает что это ошибка, свяжитесь с его создателем и попросите выслать вам приглашение', 'warning')
            return redirect(url_for('home'));


    user = db.users.find_one({'_id': ObjectId(user_id)})
    return render_template('view_schedule.html', title=schedule['name'], user=user, schedule=schedule)

@app.route('/schedules/create', methods=['GET', 'POST'])
def create_schedule():
    user_id = auth.check_session_for_token(session)
    if user_id is None:
        flash('Вам нужно быть авторизованным, чтобы создать расписание', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        if len(request.form['schedule_name']) < 1:
            return {'error': 'Заполните поле "Название"'}

        if len(request.form['schedule_name']) < 1:
            return {'error': 'Заполните поле "Название"'}

        schedule_name = request.form['schedule_name']
        alias = utils.gen_schedule_alias()
        if 'alias' in request.form:
            alias = request.form['alias']
            if len(alias) == 0:
                alias = utils.gen_schedule_alias()
            while db.schedules.find_one({'alias': alias}) is not None:
                alias = utils.gen_schedule_alias()

        availability = request.form['availability']
        first_day = request.form['first_day']
        schedule = literal_eval(request.form['schedule'])

        schedule_insert = db.schedules.insert_one({
            'name': schedule_name,
            'alias': alias,
            'availability': availability,
            'first_day': first_day,
            'creator': ObjectId(user_id),
            'moderators': [],
            'invited_users': [],
            'subscribed_users': [ObjectId(user_id)],
            'schedule': schedule,
            'changes': []
        })
        db.users.update_one({'_id': ObjectId(user_id)},
                            {"$addToSet": {'subscribed_to': ObjectId(schedule_insert.inserted_id)}})
        return '', 201

    user = db.users.find_one({'_id': ObjectId(user_id)})
    return render_template('create_schedule.html', title='Создание', user=user)

