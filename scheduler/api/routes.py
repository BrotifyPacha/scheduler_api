from scheduler import db, auth, utils
from flask import Blueprint, jsonify, request, abort, escape
from bson.objectid import ObjectId
from ast import literal_eval
from pprint import pformat
import re

api = Blueprint('api', __name__)

@api.route('/api/check_schedule_alias/<alias>', methods=['POST'])
def check_schedule_alias(alias):
    if not re.match('[A-Za-z0-9_.]+', alias):
        return jsonify({'result': 'error', 'field': 'alias'}), 400
    schedule = db.schedules.find_one({'alias': alias})
    if 'schedule_id' not in request.form:
        if schedule is None: return jsonify({'result': 'error'}), 404
        return jsonify({'result': 'success'}), 200
    else:
        schedule_id = request.form['schedule_id']
        if schedule is None: return jsonify({'result': 'error'}), 404
        if schedule['_id'] == ObjectId(schedule_id): return jsonify({'result': 'error'}), 404
        return jsonify({'result': 'success'}), 200


@api.route('/api/auth', methods=['POST'])
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


@api.route('/api/users/', methods=['POST'])
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
        'firebase_id': firebase_id
    })
    user_id = str(inserted_user.inserted_id)
    return jsonify({'token': auth.gen_signed_token(user_id)}), 201


@api.route('/api/users/<username>', methods=['GET', 'PATCH'])
@auth.authenticate()
def manage_user(username, user=None):
    print(request.method)
    if request.method == 'GET':
        user = db.users.find_one({'username': username})
        if user is None:
            abort(404)
        output = {'username': user['username']}
        return jsonify(output), 200
    elif request.method == 'PATCH':
        if not user:
            abort(403)

        username = user['username']
        password = user['password']
        if 'username' in request.form:
            username = request.form['username']
        if 'auth_password' in request.form and 'password' in request.form:
            auth_password = auth.hash_password_and_salt(request.form['auth_password'], salt=user['salt'])
            if auth_password != password:
                abort(400)
            print(request.form)
            password = auth.hash_password_and_salt(request.form['password'], salt=user['salt'])


        db.users.update_one({'_id': user['_id']}, {'$set':{
            'username': username,
            'password': password
        }})
        return '', 200
    elif request.method == 'DELETE':
        if not user:
            abort(403)
        db.users.remove_one({'_id': user['_id']})
        return '', 200


@api.route('/api/schedules/', methods=['POST'])
def add_schedule():
    user_id = auth.check_authorization_header(request)
    if user_id is None:
        abort(401)

    if 'name' not in request.args:
        abort(400)
    name = request.args['name']

    alias = utils.gen_schedule_alias()
    if 'alias' in request.args:
        alias = request.args['alias']
    if db.schedules.find_one({'alias': alias}) is not None:
        abort(400)

    privacy = request.args['availability']
    if privacy not in ['private', 'public']:
        abort(400)

    schedule = literal_eval(request.args['schedule'])
    first_day = request.args['first_day']

    schedule_insert = db.schedules.insert_one({
        'name': name,
        'alias': alias,
        'availability': privacy,
        'first_day': first_day,
        'creator': ObjectId(user_id),
        'moderators': [],
        'invited_users': [],
        'subscribed_users': [ObjectId(user_id)],
        'schedule': schedule,
        'changes': []
    })
    return '', 201


@api.route('/api/schedules/<alias>', methods=['GET', 'PUT', 'PATCH'])
@auth.authenticate()
def manage_schedule(alias, user=''):
    results = db.schedules.aggregate([
        {
            '$match': {
                'alias': alias
            }
        },
        {
            '$lookup': {
                'from': 'users',
                'localField': 'subscribed_users',
                'foreignField': '_id',
                'as': 'subscribed_users'
            }
        },
        {
            '$project': {
                'subscribed_users.firebase_id': 0,
                'subscribed_users.salt': 0,
                'subscribed_users.password': 0
            }
        },

    ])
    for result in results:
        schedule = result
    if schedule is None: abort(404)

    if request.method == 'GET':
        availability = schedule['availability']
        if availability == 'private' and (ObjectId(user['_id']) not in schedule['subscribed_users'] or
                                     ObjectId(user['_id']) not in schedule['moderators'] or
                                     ObjectId(user['_id']) != schedule['creator']):  # str нужно чтобы избавиться от ObjectId типа
            abort(401)
        output = {
            'name': schedule['name'],
            'alias': schedule['alias'],
            'availability': schedule['availability'],
            'first_day': schedule['first_day'],
            'creator': schedule['creator'],
            'moderators': schedule['moderators'],
            'invited_users': schedule['invited_users'],
            'subscribed_users': schedule['subscribed_users'],
            'schedule': schedule['schedule'],
            'changes': schedule['changes']
        }
        return str(output), 200
    elif request.method == 'PUT':
        if ObjectId(user['_id']) not in schedule['moderators'] and ObjectId(user['_id']) != schedule['creator']:
            abort(401)
        change = {
            'date': request.args['date'],
            'change': literal_eval(request.args['change'])
        }
        db.schedules.update_one({'_id': schedule['_id']}, {'$pull': {'changes': {'date': change['date']}}})
        db.schedules.update_one({'_id': schedule['_id']}, {'$addToSet': {'changes': change}})
        return ''
    elif request.method == 'PATCH':
        if 'name' in request.args:
            schedule['name'] = request.args['name']
        if 'alias' in request.args:
            schedule['alias'] = request.args['alias']
        if 'availability' in request.args:
            if request.args['availability'] not in ['private', 'public']:
                abort(400)
            schedule['availability'] = request.args['availability']
        if 'first_day' in request.args:
            schedule['first_day'] = request.args['first_day']
        if 'schedule' in request.args:
            schedule['schedule'] = request.args['schedule']

        db.schedules.update_one({'_id': schedule['_id']}, {'$set': {
            'name': schedule['name'],
            'alias': schedule['alias'],
            'availability': schedule['availability'],
            'first_day': schedule['first_day'],
            'creator': ObjectId(schedule['creator']),
            'moderators': schedule['moderators'],
            'invited_users': schedule['invited_users'],
            'subscribed_users': schedule['subscribed_users'],
            'schedule': schedule['schedule'],
            'changes': schedule['changes']
        }})
        return ''


@api.route('/api/schedules/<alias>/invite/<username>', methods=['POST', 'DELETE'])
def invite_user(alias, username):
    requesting_user_id = auth.check_authorization_header(request)
    if requesting_user_id is None:
        abort(401)
    schedule = db.schedules.find_one({'alias': alias})
    user = db.users.find_one({'username': username})
    if schedule is None or user is None:
        abort(404)

    # Проверяем есть ли пользователя права на приглашение других пользователей
    if ObjectId(requesting_user_id) not in schedule['moderators'] and ObjectId(requesting_user_id) != schedule['creator']:
        abort(401)

    if request.method == 'POST':
        # Проверяем не себя ли хочет пригласить пользователь, или если этот пользователь уже подписан или приглашён
        if requesting_user_id == user['_id'] or ObjectId(user['_id']) in schedule['subscribed_users'] or ObjectId(
                user['_id']) in schedule['invited_users']:
            return ''
        db.schedules.update_one({'_id': schedule['_id']}, {'$addToSet': {'invited_users': ObjectId(user['_id'])}})
    elif request.method == 'DELETE':
        db.schedules.update_one({'_id': schedule['_id']}, {'$pull': {'invited_users': ObjectId(user['_id'])}})
    return ''


@api.route('/api/schedules/<alias>/invite/accept', methods=['POST'])
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
    return ''


@api.route('/api/schedules/<alias>/invite/reject', methods=['POST'])
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
    return ''


@api.route('/api/schedules/<alias>/subscribe', methods=['POST', 'DELETE'])
def subscribe_to_schedule(alias):
    user_id = auth.check_authorization_header(request)
    if user_id is None:
        abort(401)

    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        abort(404)

    if request.method == 'POST':
        if schedule['availability'] == 'private' and (ObjectId(user_id) not in schedule['invited_users'] or ObjectId(user_id) != schedule['creator']):
            abort(401)
        if ObjectId(user_id) in schedule['subscribed_users']:
            return ''

        db.schedules.update_one({'_id': ObjectId(schedule['_id'])}, {'$addToSet': {'subscribed_users': ObjectId(user_id)},
                                                           '$pull': {'invited_users': ObjectId(user_id)}})
    elif request.method == 'DELETE':
        if ObjectId(user_id) in schedule['subscribed_users']:
            db.schedules.update_one({'_id': ObjectId(schedule['_id'])}, {'$pull': {
                                                                            'subscribed_users': ObjectId(user_id),
                                                                            'moderators': ObjectId(user_id)}})
    return ''


@api.route('/api/schedules/<alias>/promote/<username>', methods=['POST', 'DELETE'])
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
                                    {'$pull': {'moderators': ObjectId(user['_id'])}})


@api.route('/api/search', methods=['POST'])
def search():
    return