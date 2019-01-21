from scheduler import app, db, auth, utils
from flask import jsonify, request, abort, escape
from bson.objectid import ObjectId
from ast import literal_eval


@app.route('/api/auth', methods=['POST'])
def authorization():
    username = escape(request.args['username']).lower()
    password = request.args['password']

    user = db.users.find_one({'username': username})
    if user is None:
        abort(400)

    salt = user['salt']
    salted_password = auth.hash_password_and_salt(password, salt)
    if not auth.check_password(password, salt, salted_password):
        abort(400)
    user_id = str(user['_id'])

    if 'firebase_id' in request.args:
        firebase_id = request.args['firebase_id']
        db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'firebase_id': firebase_id}})
    return jsonify({'token': auth.gen_signed_token(user_id)})


@app.route('/api/users/', methods=['POST'])
def add_user():
    username = escape(request.args['username']).lower()
    password = request.args['password']
    firebase_id = ''
    if 'firebase_id' in request.args:
        firebase_id = request.args['firebase_id']

    if db.users.find_one({'username': username}) is not None:
        abort(400)

    salt = auth.gen_salt()
    salted_password = auth.hash_password_and_salt(password, salt)
    inserted_user = db.users.insert_one({
        'username': username,
        'password': salted_password,
        'salt': salt,
        'invited_to': [],
        'subscribed_to': [],
        'firebase_id': firebase_id
    })
    user_id = str(inserted_user.inserted_id)
    return jsonify({'token': auth.gen_signed_token(user_id)}), 201


@app.route('/api/users/<username>', methods=['GET'])
def get_user(username):
    user = db.users.find_one({'username': username})
    if user is None:
        abort(404)
    output = {'username': user['username'], 'firebase_id': user['firebase_id'], 'invited_to': user['invited_to'],
              'subscribed_to': user['subscribed_to']}
    return jsonify(output), 200  # response code - 200


@app.route('/api/schedules/', methods=['POST'])
def add_schedule():
    user_id = auth.check_authorization_header(request)
    if user_id is None:
        abort(401)

    alias = utils.gen_schedule_alias()
    if 'alias' in request.args:
        alias = request.args['alias']
    if db.schedules.find_one({'alias': alias}) is not None:
        abort(400)

    privacy = request.args['privacy']
    if privacy not in ['private', 'public']:
        abort(400)

    schedule = literal_eval(request.args['schedule'])
    first_week_start = request.args['first_week_start']

    schedule_insert = db.schedules.insert_one({
        'alias': alias,
        'privacy': privacy,
        'first_week_start': first_week_start,
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


@app.route('/api/schedules/<alias>', methods=['GET', 'PUT', 'PATCH'])
def manage_schedule(alias):
    # проверяем авторизован ли пользователь
    user_id = auth.check_authorization_header(request)
    if user_id is None:
        abort(401)

    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None: abort(404)

    if request.method == 'GET':
        privacy = schedule['privacy']
        if privacy == 'private' and (ObjectId(user_id) not in schedule['subscribed_users'] or
                                     ObjectId(user_id) not in schedule['moderators'] or
                                     ObjectId(user_id) != schedule[
                                         'creator']):  # str нужно чтобы избавиться от ObjectId типа
            abort(401)
        output = {
            'alias': schedule['alias'],
            'privacy': schedule['privacy'],
            'first_week_start': schedule['first_week_start'],
            'creator': schedule['creator'],
            'moderators': schedule['moderators'],
            'invited_users': schedule['invited_users'],
            'subscribed_users': schedule['subscribed_users'],
            'schedule': schedule['schedule'],
            'changes': schedule['changes']
        }
        return str(output), 200
    elif request.method == 'PUT':
        if ObjectId(user_id) not in schedule['moderators'] and ObjectId(user_id) != schedule['creator']:
            abort(401)
        change = {
            'date': request.args['date'],
            'change': literal_eval(request.args['change'])
        }
        db.schedules.update_one({'_id': schedule['_id']}, {'$pull': {'changes': {'date': change['date']}}})
        db.schedules.update_one({'_id': schedule['_id']}, {'$addToSet': {'changes': change}})
        return ''
    elif request.method == 'PATCH':
        if 'alias' in request.args:
            schedule['alias'] = request.args['alias']
        if 'privacy' in request.args:
            if request.args['privacy'] not in ['private', 'public']:
                abort(400)
            schedule['privacy'] = request.args['privacy']
        if 'first_week_start' in request.args:
            schedule['first_week_start'] = request.args['first_week_start']
        if 'schedule' in request.args:
            schedule['schedule'] = request.args['schedule']

        db.schedules.update_one({'_id': schedule['_id']}, {'$set': {
            'alias': schedule['alias'],
            'privacy': schedule['privacy'],
            'first_week_start': schedule['first_week_start'],
            'creator': ObjectId(schedule['creator']),
            'moderators': schedule['moderators'],
            'invited_users': schedule['invited_users'],
            'subscribed_users': schedule['subscribed_users'],
            'schedule': schedule['schedule'],
            'changes': schedule['changes']
        }})
        return ''


@app.route('/api/schedules/<alias>/invite/<username>', methods=['POST', 'DELETE'])
def invite_user(alias, username):
    requesting_user_id = auth.check_authorization_header(request)
    if requesting_user_id is None:
        abort(401)
    schedule = db.schedules.find_one({'alias': alias})
    user = db.users.find_one({'username': username})
    if schedule is None or user is None:
        abort(404)

    # Проверяем есть ли пользователя права на приглашение других пользователей
    if ObjectId(requesting_user_id) not in schedule['moderators'] and ObjectId(requesting_user_id) != schedule[
        'creator']:
        abort(401)

    if request.method == 'POST':
        # Проверяем не себя ли хочет пригласить пользователь, или если этот пользователь уже подписан или приглашён
        if requesting_user_id == user['_id'] or ObjectId(user['_id']) in schedule['subscribed_users'] or ObjectId(
                user['_id']) in schedule['invited_users']:
            return ''
        db.schedules.update_one({'_id': schedule['_id']}, {'$addToSet': {'invited_users': ObjectId(user['_id'])}})
        db.users.update_one({'_id': user['_id']}, {'$addToSet': {'invited_to': ObjectId(schedule['_id'])}})
    elif request.method == 'DELETE':
        db.schedules.update_one({'_id': schedule['_id']}, {'$pull': {'invited_users': ObjectId(user['_id'])}})
        db.users.update_one({'_id': user['_id']}, {'$pull': {'invited_to': ObjectId(schedule['_id'])}})
    return ''


@app.route('/api/schedules/<alias>/invite/accept', methods=['POST'])
def accept_invitation(alias):
    user_id = auth.check_authorization_header(request)
    if user_id is None:
        abort(401)
    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        abort(404)
    if ObjectId(user_id) not in schedule['invited_users']:
        abort(404)

    db.schedules.update_one({'_id': ObjectId(schedule['_id'])}, {'$pull': {'invited_users': ObjectId(user_id)},
                                                                 '$addToSet': {'subscribed_users': ObjectId(user_id)}})
    db.users.update_one({'_id': ObjectId(user_id)}, {'$pull': {'invited_to': ObjectId(schedule['_id'])},
                                                     '$addToSet': {'subscribed_to': ObjectId(schedule['_id'])}})
    return ''


@app.route('/api/schedules/<alias>/invite/reject', methods=['POST'])
def reject_invitation(alias):
    user_id = auth.check_authorization_header(request)
    if user_id is None:
        abort(401)
    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        abort(404)
    if ObjectId(user_id) not in schedule['invited_users']:
        abort(404)
    db.schedules.update_one({'_id': ObjectId(schedule['_id'])}, {'$pull': {'invited_users': ObjectId(user_id)}})
    db.users.update_one({'_id': ObjectId(user_id)}, {'$pull': {'invited_to': ObjectId(schedule['_id'])}})
    return ''


@app.route('/api/schedules/<alias>/subscribe', methods=['POST', 'DELETE'])
def subscribe_to_schedule(alias):
    user_id = auth.check_authorization_header(request)
    if user_id is None:
        abort(401)

    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        abort(404)

    if request.method == 'POST':
        if schedule['privacy'] == 'private':
            abort(404)
        if ObjectId(user_id) in schedule['subscribed_users']:
            return ''

        db.schedules.update_one({'_id': schedule['_id']}, {'$addToSet': {'subscribed_users': ObjectId(user_id)},
                                                           '$pull': {'invited_users': ObjectId(user_id)}})
        db.users.update_one({'_id': ObjectId(user_id)}, {'$addToSet': {'subscribed_to': ObjectId(schedule['_id'])},
                                                         '$pull': {'invited_to': ObjectId(schedule['_id'])}})
    elif request.method == 'DELETE':
        if ObjectId(user_id) in schedule['subscribed_users']:
            db.schedules.update_one({'_id': schedule['_id']}, {'$pull': {'subscribed_users': ObjectId(user_id),
                                                                         'moderators': ObjectId(user_id)}})
            db.users.update_one({'_id': ObjectId(user_id)}, {'$pull': {'subscribed_to': ObjectId(schedule['_id'])}})
    return ''


@app.route('/api/schedules/<alias>/promote/<username>', methods=['POST', 'DELETE'])
def promote_user(alias, username):
    requesting_user_id = auth.check_authorization_header(request)
    if requesting_user_id is None:
        abort(401)

    schedule = db.schedules.find_one({'alias': alias})
    user = db.users.find_one({'username': username})
    if schedule is None or user is None:
        abort(404)

    if ObjectId(requesting_user_id) != schedule['creator']:
        abort(401)

    if ObjectId(user['_id']) in schedule['subscribed_users']:
        if request.method == 'POST':
            db.schedules.update_one({'_id': ObjectId(schedule['_id'])},
                                    {'$addToSet': {'moderators': ObjectId(user['_id'])}})
        elif request.method == 'DELETE':
            db.schedules.update_one({'_id': ObjectId(schedule['_id'])},
                                    {'pull': {'moderators': ObjectId(user['_id'])}})
