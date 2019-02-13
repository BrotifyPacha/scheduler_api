from scheduler import app, db, auth
from flask import render_template, request, session, redirect, url_for, flash, jsonify
from bson.objectid import ObjectId
from scheduler import utils
from ast import literal_eval
import re

error_schedule_not_found = 'Расписания по данной ссылке не существует'

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
        return render_template('home.html', user=user, schedules=schedules)
    return render_template('home.html')


@app.route('/search/', methods= ['POST'])
def search():
    if 'query' in request.form:
        query = request.form['query']
    return redirect(url_for('search_with', query=query))

@app.route('/search/<query>', methods= ['GET'])
def search_with(query):
    user_id = auth.check_session_for_token(session)
    print(query)
    schedules = db.schedules.find(
        {
            '$and': [
                {'availability': 'public'},
                {'$or': [
                    {'alias': query},
                    {'name': query}
                ]}
            ]
        })
    if user_id is None:
        return render_template('search_result.html', title='Поиск', schedules=schedules)
    user = db.users.find_one({'_id':ObjectId(user_id)})
    return render_template('search_result.html', title='Поиск', schedules=schedules, user=user)

@app.route('/schedules/<alias>')
def view_schedule(alias):
    user_id = auth.check_session_for_token(session)

    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        flash(error_schedule_not_found, 'warning')
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
        return redirect(url_for('home')), 401

    if request.method == 'POST':
        if len(request.form['schedule_name']) < 1:
            return jsonify({'result': 'error', 'field': 'schedule_name'}), 400

        schedule_name = request.form['schedule_name']
        alias = utils.gen_schedule_alias()
        if 'alias' in request.form:
            alias = request.form['alias']
            if db.schedules.find_one({'alias': alias}) is not None:
                return jsonify({'result': 'error', 'field': 'alias'}), 400
            if len(alias) == 0:
                alias = utils.gen_schedule_alias()
                while db.schedules.find_one({'alias': alias}) is not None:
                    alias = utils.gen_schedule_alias()

        availability = request.form['availability']

        if availability not in ['public', 'private']:
            return jsonify({'result': 'error', 'field': 'availability'}), 400

        first_day = request.form['first_day']
        schedule = literal_eval(request.form['schedule'])

        if len(schedule) > 1 and not re.match('\d{2}\.\d{2}\.\d{2}', first_day):
            return jsonify({'result': 'error', 'field': 'first_day'}), 400

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
        return jsonify({'result': 'success'}), 201

    user = db.users.find_one({'_id': ObjectId(user_id)})
    return render_template('manage_schedule.html', title='Создание', user=user)

@app.route('/schedules/<alias>/edit', methods=['GET', 'POST'])
def edit_schedule(alias):
    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        flash(error_schedule_not_found, 'warning')
        return redirect(url_for('home')), 404

    user_id = auth.check_session_for_token(session)
    if user_id is None or (ObjectId(user_id) != schedule['creator'] and ObjectId(user_id) not in schedule['moderators']):
        flash('Нехватает прав на редактирование этого расписания', 'danger')
        return redirect(url_for('home')), 401

    if request.method == 'POST':
        schedule_id = request.form['schedule_id']
        if len(request.form['schedule_name']) < 1:
            return jsonify({'result': 'error', 'field': 'schedule_name'}), 400

        schedule_name = request.form['schedule_name']
        alias = utils.gen_schedule_alias()
        if 'alias' in request.form:
            alias = request.form['alias']
            schedule = db.schedules.find_one({'alias': alias})
            if schedule is not None and schedule['_id'] != ObjectId(schedule_id):
                return jsonify({'result': 'error', 'field': 'alias'}), 400
            if len(alias) == 0:
                alias = utils.gen_schedule_alias()
                while db.schedules.find_one({'alias': alias}) is not None:
                    alias = utils.gen_schedule_alias()



        availability = request.form['availability']

        if availability not in ['public', 'private']:
            return jsonify({'result': 'error', 'field': 'availability'}), 400

        first_day = request.form['first_day']
        schedule = literal_eval(request.form['schedule'])

        if len(schedule) > 1 and not re.match('\d{2}\.\d{2}\.\d{2}', first_day):
            return jsonify({'result': 'error', 'field': 'first_day'}), 400

        schedule_update = db.schedules.update_one({'_id': ObjectId(schedule_id)}, { '$set':{
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
        }})
        return jsonify({'result': 'success'}), 201

        return

    user = db.users.find_one({'_id': ObjectId(user_id)})
    return render_template('manage_schedule.html', title='Редактирование', user=user, schedule=schedule)


@app.route('/schedules/<alias>/delete', methods=['POST'])
def delete_schedule(alias):
    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        flash(error_schedule_not_found, 'warning')
        return redirect(url_for('home')), 404

    user_id = auth.check_session_for_token(session)
    if user_id is None or ObjectId(user_id) != schedule['creator']:
        flash('Нехватает прав на удаление этого расписания', 'danger')
        return redirect(url_for('home')), 401

    db.schedules.delete_one({'_id':schedule['_id']})
    flash('Расписание "%s" было успешно удалено' % schedule['name'], 'success');
    return redirect(url_for('home'))

@app.route('/schedules/<alias>/subscribe', methods=['POST'])
def subscribe(alias):
    user_id = auth.check_session_for_token(session)
    if user_id is None:
        flash('Для того чтобы подписаться на расписание необходимо быть авторизовным')
        return '', 401

    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        flash(error_schedule_not_found, 'warning')
        return '', 404

    if schedule['availability'] == 'private' and (
            ObjectId(user_id) not in schedule['invited_users'] or ObjectId(user_id) != schedule['creator']):
        flash(
            'Это приватное расписание и подписаться на него можно лишь получив приглашение от его модератора или создателя',
            'warning')
        return '', 401

    if ObjectId(user_id) in schedule['subscribed_users']:
        return '', 200

    db.schedules.update_one({'_id': schedule['_id']}, {'$addToSet': {{'subscribed_users': ObjectId(user_id)}},
                                                       '$pull': {'invited_users': ObjectId(user_id)}})
    return '', 200

@app.route('/schedules/<alias>/unsubscribe', methods=['POST'])
def unsubscribe(alias):
    user_id = auth.check_session_for_token(session)
    if user_id is None:
        flash('Для того чтобы отписаться от расписания необходимо быть авторизовным')
        return '', 401

    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        flash(error_schedule_not_found, 'warning')
        return '', 404

    if ObjectId(user_id) not in schedule['subscribed_users']:
        return '', 200

    db.schedules.update_one({'_id': schedule['_id']}, {'$pull': {{'subscribed_users': ObjectId(user_id)},
                                                                 {'moderators': ObjectId(user_id)}}})
    return '', 200




