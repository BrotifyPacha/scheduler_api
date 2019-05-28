from scheduler import db, utils
from scheduler.api.aggr_utils import *
from scheduler.api import auth
from flask import Blueprint, jsonify, request, abort, escape, redirect
from bson.objectid import ObjectId
from bson.int64 import Int64
from ast import literal_eval
import re
import datetime

api = Blueprint('api', __name__)
"""
При регистрации поля логин и пароль должны удовлетворять всем критериям
Username:
1. min length = 3
2. a-z0-9_.-
3. only one _ . - in a row
4. username must not be already taken
Password:
- min length = 6
При создании новоого расписания его поля должны удовлетворять всем критериям
Schedule_Name:
1. min length = 3
Alias:
1. min length = 3
2. A-Za-z0-9_.-
3. only one _ or - in a row
4. alias must not be already taken
"""

MIN_USERNAME_LENGTH = 5
MIN_PASSWORD_LENGTH = 6

MIN_NAME_LENGTH = 3
MIN_ALIAS_LENGTH = 3
USERNAME_MATCH_REGEX = '[a-z0-9_.-]+'
ALIAS_MATCH_REGEX = '[A-Za-z0-9_.-]+'
WRONG_CREDENTIALS = 'wrong_credentials'

def get_args():
    result = {}
    for key, value in request.args.items():
        result[key] = value
    for key, value in request.form.items():
        if key not in result:
            result[key] = value
    return result


@api.route('/api/authenticate', methods=['POST'])
def authorization():
    print(f"authorization = {get_args()}")
    username = escape(get_args()['username']).lower()
    password = get_args()['password']
    user = db.users.find_one({'username': username})
    if user is None:
        return json_error(WRONG_CREDENTIALS)

    salt = user['salt']
    if not auth.check_password(password, salt, user["password"]):
        return json_error(WRONG_CREDENTIALS)
    user_id = str(user['_id'])


    if 'firebase_id' in get_args():
        firebase_id = get_args()['firebase_id']
        db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'firebase_id': firebase_id}})


    print(f"authorization: id = {user_id} token = {auth.gen_signed_token(user_id)}")
    return json_success(data={'token': auth.gen_signed_token(user_id)}), 200



@api.route("/api/users_self", methods=["GET"])
@auth.authenticate()
def get_user_self(user=None):
    if not user:
        return json_error("not authorized"), 200
    print(f"get_user_self = {user}")
    return manage_single_user(username=user["username"])


@api.route('/api/users/', methods=['GET', 'POST'])
@auth.authenticate()
def manage_users(user=None):
    if request.method == 'GET':
        match_fields = {}
        return_fields = None
        limit_int = None
        skip_int = None
        whitelist_match_keys = ['username', '_id']
        whitelist_return_fields = ['_id', 'username', 'schedules']

        current_field = ''
        try:
            current_field = 'match_fields'
            if 'match_fields' in request.args:
                match_fields = literal_eval(request.args['match_fields'])
            current_field = 'return_fields'
            if 'return_fields' in request.args:
                return_fields = literal_eval(request.args['return_fields'])
            current_field = 'limit'
            if 'limit' in request.args:
                limit_int = int(request.args['limit'])
            current_field = 'skip'
            if 'skip' in request.args:
                skip_int = int(request.args['skip'])
        except:
            return json_error(type='field', field=current_field)

        match_fields = whitelist_arr(whitelist_match_keys, match_fields)
        match = parse_match_stage(match_fields, get_regex_wrapper('.*', '.*'))

        aggregation = get_basic_user_aggregation()
        aggregation.append({'$match': match})
        result_obj = db.users.aggregate(aggregation)
        aggregated_result = []
        for item in result_obj:
            aggregated_result.append(item)

        if skip_int is not None:
            aggregated_result = skip(skip_int, aggregated_result)
        if limit_int is not None:
            aggregated_result = limit(limit_int, aggregated_result)

        if return_fields:
            return_fields = whitelist_arr(whitelist_return_fields, return_fields)
            aggregated_result = [whitelist_arr(return_fields, item) for item in aggregated_result]

        for found_user in aggregated_result:
            if 'schedules' not in found_user:
                break
            found_user['schedules'] = return_only_visible(user=user, schedules=found_user['schedules'])

        return json_success(objectid_to_str(aggregated_result))
    elif request.method == 'POST':
        username = escape(request.args['username']).lower()
        password = request.args['password']

        result = verify_username(username)
        if result is not None:
            return result
        result = verify_password(password)
        if result is not None:
            return result

        firebase_id = ''
        if 'firebase_id' in request.args:
            firebase_id = request.args['firebase_id']

        salt = auth.gen_salt()
        salted_password = auth.hash_password_and_salt(password, salt)
        inserted_user = db.users.insert_one({
            'username': username,
            'password': salted_password,
            'salt': salt,
            'firebase_id': firebase_id
        })
        user_id = str(inserted_user.inserted_id)
        return json_success(data={'token': auth.gen_signed_token(user_id)}), 201


@api.route('/api/users/<username>', methods=['GET', 'PATCH'])
@auth.authenticate()
def manage_single_user(username, user=None):
    username = username.lower()
    if request.method == 'GET':
        return_fields = None
        #whitelist_return_fields = ['_id', 'username', 'schedules']

        if 'return_fields' in get_args():
            try:
                return_fields = literal_eval(get_args()['return_fields'])
                #return_fields = whitelist_arr(whitelist_return_fields, return_fields)
            except:
                return json_error(type='field', field='return_fields')

        aggregation = get_basic_user_aggregation()
        aggregation.append({'$match': {'username': username}})
        result_obj = db.users.aggregate(aggregation)
        found_user = None
        for item in result_obj:
            found_user = item

        if not found_user:
            return json_error('not found'), 200

        if return_fields:
            found_user = whitelist_arr(return_fields, found_user)

        if 'schedules' in found_user:
            found_user['schedules'] = return_only_visible(user=user, schedules=found_user['schedules'])
        
        return json_success(objectid_to_str(found_user))

    elif request.method == 'PATCH':
        if not user or username != user['username']:
            return json_error('not authorized'), 200
        user = db.users.find_one({'_id': user["_id"]})
        username = user['username']
        password = user['password']
        if 'username' in get_args():
            username = get_args()['username']
            verify_username(username)


        print("patching user")
        if 'auth_password' in get_args() and 'password' in get_args():
            print("changing password")
            auth_password = auth.hash_password_and_salt(get_args()['auth_password'], salt=user['salt'])
            new_password = get_args()['password']
            if verify_password(new_password) is not None:
                return verify_password(new_password)

            if auth_password != password:
                return json_error('field', field='auth_password'), 200
            print(f'new password = {new_password}')
            password = auth.hash_password_and_salt(new_password, salt=user['salt'])
        db.users.update_one({'_id': user['_id']}, {'$set':{
            'username': username,
            'password': password
        }})
        return json_success(), 200
    elif request.method == 'DELETE':
        if not user or username != user['username']:
            return json_error('not authorized'), 200
        db.users.remove_one({'_id': user['_id']})
        return json_success(), 200


@api.route('/api/schedules/', methods=['GET', 'POST'])
@auth.authenticate()
def manage_schedules(user=None):
    if request.method == 'GET':
        match_fields = {}
        return_fields = None
        limit_int = None
        skip_int = None

        current_field = ''
        try:
            current_field = 'match_fields'
            if 'match_fields' in request.args:
                match_fields = literal_eval(request.args['match_fields'])
            current_field = 'return_fields'
            if 'return_fields' in request.args:
                return_fields = literal_eval(request.args['return_fields'])
            current_field = 'limit'
            if 'limit' in request.args:
                limit_int = int(request.args['limit'])
            current_field = 'skip'
            if 'skip' in request.args:
                skip_int = int(request.args['skip'])
        except:
            return json_error(type='field', field=current_field), 200

        match = parse_match_stage(match_fields, get_regex_wrapper(pre='.*', post='.*'))
        aggregation = get_basic_schedule_aggregation()
        aggregation.append({'$match': match})
        result_obj = db.schedules.aggregate(aggregation)
        aggregated_result = []
        for item in result_obj:
            aggregated_result.append(item)

        shown_schedules = return_only_visible(user=user, schedules=aggregated_result)

        if return_fields is not None:
            shown_schedules = [whitelist_arr(return_fields, item) for item in shown_schedules]

        if skip_int is not None:
            shown_schedules = skip(skip_int, shown_schedules)
        if limit_int is not None:
            shown_schedules = limit(limit_int, shown_schedules)
        return json_success(objectid_to_str(shown_schedules))
    elif request.method == 'POST':
        if not user:
            return json_error('not authorized'), 200
        current_field = ''
        try:
            current_field = 'name'
            name = request.args['name']
            if len(name) < 3:
                return json_error(type='field', field='name'), 200
            current_field = 'alias'
            alias = utils.gen_schedule_alias()
            if 'alias' in request.args:
                alias = request.args['alias']
            verify_alias(alias)
            current_field = 'availability'
            privacy = request.args['availability']
            if privacy not in ['private', 'public']:
                return json_error(type='field', field='availability'), 200
            current_field = 'first_day'
            first_day = request.args['first_day']
            current_field = 'schedule'
            schedule = literal_eval(request.args['schedule'])
        except:
            return json_error(type='field', field=current_field), 200

        schedule_insert = db.schedules.insert_one({
            'name': name,
            'alias': alias,
            'availability': privacy,
            'first_day': first_day,
            'creator': ObjectId(user['_id']),
            'moderators': [],
            'invited_users': [],
            'subscribed_users': [ObjectId(user['_id'])],
            'schedule': schedule,
            'changes': []
        })
        return json_success(), 200


@api.route('/api/schedules/<alias>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
@auth.authenticate()
def manage_single_schedule(alias, user=None):
    schedule = db.schedules.find_one({'alias': alias})
    if not schedule:
        return json_error('not found'), 200

    if request.method == 'GET':
        availability = schedule['availability']
        if availability == 'private' and (
                not user or
                ObjectId(user['_id']) not in schedule['subscribed_users'] or
                ObjectId(user['_id']) != schedule['creator']):  # str нужно чтобы избавиться от ObjectId типа
            return json_error('not found'), 200
        return_fields = None
        if 'return_fields' in request.args:
           try:
               return_fields = literal_eval(request.args['return_fields'])
           except:
               return json_error('field', field='return_fields'), 200

        aggregation = get_basic_schedule_aggregation()
        aggregation.append({'$match': {'alias': alias}})
        aggr_result = db.schedules.aggregate(aggregation)
        for item in aggr_result:
            schedule = item

        projected_schedule = whitelist_arr(return_fields, schedule)
        return json_success(projected_schedule), 200
    elif request.method == 'PUT':
        if ObjectId(user['_id']) not in schedule['moderators'] and ObjectId(user['_id']) != schedule['creator']:
            return json_error(type='not authorized'), 200

        current_field = None
        try:
            current_field = 'date'
            date_long = request.args[current_field]
            now_long = datetime.datetime.now().timestamp()
            change_date = datetime.datetime.fromtimestamp(date_long).date()
            now_date = datetime.datetime.fromtimestamp(now_long).date()
            if now_long <= date_long or change_date==now_date:
                return json_error(type='field', field=current_field), 200

            current_field = 'change'
            change = literal_eval(request.args[current_field])
        except:
            return json_error(type='field', field=current_field), 200
        change = {
            'date': Int64(date_long),
            'change': change
        }
        db.schedules.update_one({'_id': schedule['_id']}, {'$pull': {'changes': {'date': change['date']}}})
        db.schedules.update_one({'_id': schedule['_id']}, {'$addToSet': {'changes': change}})
        return ''
    elif request.method == 'PATCH':
        if ObjectId(user['_id']) not in schedule['moderators'] and ObjectId(user['_id']) != schedule['creator']:
            return json_error(type='not authorized'), 200
        if 'name' in request.args:
            schedule['name'] = request.args['name']
        if 'alias' in request.args:
            schedule['alias'] = request.args['alias']
        if 'availability' in request.args:
            if request.args['availability'] not in ['private', 'public']:
                return json_error(type='field', field='availability'), 200
            schedule['availability'] = request.args['availability']
        if 'first_day' in request.args:
            schedule['first_day'] = request.args['first_day']
        if 'schedule' in request.args:
            try:
                schedule['schedule'] = literal_eval(request.args['schedule'])
            except:
                json_error(type='field', field='schedule'), 200

        db.schedules.update_one({'_id': schedule['_id']}, {'$set': {
            'name': schedule['name'],
            'alias': schedule['alias'],
            'availability': schedule['availability'],
            'first_day': Int64(schedule['first_day']),
            'creator': ObjectId(schedule['creator']),
            'moderators': schedule['moderators'],
            'invited_users': schedule['invited_users'],
            'subscribed_users': schedule['subscribed_users'],
            'schedule': schedule['schedule'],
            'changes': schedule['changes']
        }})
        return json_success(), 200
    elif request.method == 'DELETE':
        if ObjectId(user['_id']) != schedule['creator']:
            return json_error('not authorized'), 200

        if 'alias' not in request.args:
            return json_error(type='field', field='alias'), 200

        if schedule['alias'] == request.args['alias']:
            db.schedules.remove_one({'alias': alias})
        return json_success(), 200

@api.route('/api/schedules/<alias>/invite/<username>', methods=['POST', 'DELETE'])
@auth.authenticate()
def invite_user(alias, username, user=None):
    if not user:
        return json_error(type='not_authorized'), 200
    schedule = db.schedules.find_one({'alias': alias})
    invited_user = db.users.find_one({'username': username})
    if schedule is None or invited_user is None:
        return json_error(type='not found'), 200

    # Проверяем есть ли пользователя права на приглашение других пользователей
    if ObjectId(user['_id']) not in schedule['moderators'] and ObjectId(user['_id']) != schedule['creator']:
        return json_error(type='not_authorized'), 200

    if request.method == 'POST':
        # Проверяем не себя ли хочет пригласить пользователь, или если этот пользователь уже подписан или приглашён
        if invited_user['_id'] == user['_id'] or ObjectId(invited_user['_id']) in schedule['subscribed_users'] or \
                ObjectId(invited_user['_id']) in schedule['invited_users']:
            return json_success(), 200
        db.schedules.update_one({'_id': schedule['_id']}, {'$addToSet': {'invited_users': ObjectId(invited_user['_id'])}})
    elif request.method == 'DELETE':
        db.schedules.update_one({'_id': schedule['_id']}, {'$pull': {'invited_users': ObjectId(invited_user['_id'])}})
    return json_success(), 200


@api.route('/api/schedules/<alias>/accept_invite', methods=['POST'])
@auth.authenticate()
def accept_invitation(alias, user=None):
    if not user:
        return json_error(type='not_authorized'), 200
    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        return json_error(type='not found'), 200
    if ObjectId(user['_id']) not in schedule['invited_users']:
        return json_error(type='not found'), 200
    db.schedules.update_one({'_id': ObjectId(schedule['_id'])}, {'$pull': {'invited_users': ObjectId(user['_id'])},
                                                                 '$addToSet': {'subscribed_users': ObjectId(user['_id'])}})
    return json_success(), 200


@api.route('/api/schedules/<alias>/reject_invite', methods=['POST'])
@auth.authenticate()
def reject_invitation(alias, user=None):
    if not user:
        return json_error(type='not_authorized'), 200
    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        return json_error(type='not found'), 200
    if ObjectId(user['_id']) not in schedule['invited_users']:
        return json_error(type='not found'), 200
    db.schedules.update_one({'_id': ObjectId(schedule['_id'])}, {'$pull': {'invited_users': ObjectId(user['_id'])}})
    return json_success(), 200


@api.route('/api/schedules/<alias>/subscribe', methods=['POST', 'DELETE'])
@auth.authenticate()
def subscribe_to_schedule(alias, user=None):
    if not user:
        return json_error('not authorized'), 200

    schedule = db.schedules.find_one({'alias': alias})
    if schedule is None:
        return json_error('not found'), 200
    user_id = ObjectId(user['_id'])
    if request.method == 'POST':
        if schedule['availability'] == 'private' and \
                (user_id not in schedule['invited_users'] or user_id != ObjectId(schedule['creator'])):
            return json_error('not authorized'), 200
        if user_id in schedule['subscribed_users']:
            return json_success(), 200
        db.schedules.update_one({'_id': ObjectId(schedule['_id'])}, {
            '$addToSet': {'subscribed_users': user_id},
            '$pull': {'invited_users': user_id}
        })
    elif request.method == 'DELETE':
        if user_id in schedule['subscribed_users']:
            db.schedules.update_one({'_id': ObjectId(schedule['_id'])}, {
                '$pull': {
                    'subscribed_users': user_id,
                    'moderators': user_id
                }
            })
    return json_success(), 200


@api.route('/api/schedules/<alias>/promote/<username>', methods=['POST', 'DELETE'])
@auth.authenticate()
def promote_user(alias, username, user=None):
    if not user:
        return json_error('not authorized'), 200

    schedule = db.schedules.find_one({'alias': alias})
    user_to_promote = db.users.find_one({'username': username})
    if schedule is None or user_to_promote is None:
        return json_error('not found'), 200

    if ObjectId(user['_id']) != schedule['creator']:
        return json_error('not authorized'), 200

    if ObjectId(user_to_promote['_id']) in schedule['subscribed_users']:
        if request.method == 'POST':
            db.schedules.update_one({'_id': ObjectId(schedule['_id'])},
                                    {'$addToSet': {'moderators': ObjectId(user_to_promote['_id'])}})
        elif request.method == 'DELETE':
            db.schedules.update_one({'_id': ObjectId(schedule['_id'])},
                                    {'$pull': {'moderators': ObjectId(user_to_promote['_id'])}})
    return json_success(), 200

def verify_username(username):
    if len(username) < MIN_USERNAME_LENGTH:
        return json_error(type='field', field='username', description='error_1'), 200
    if not re.match(USERNAME_MATCH_REGEX, username):
        return json_error(type='field', field='username', description='error_2'), 200
    if re.match('.*__.*', username) or re.match('.*\-\-.*', username) or re.match('.*\.\..*', username):
        return json_error(type='field', field='username', description='error_3'), 200
    if db.users.find_one({'username': username}) is not None:
        return json_error(type='field', field='username', description='error_4'), 200
    return None

def verify_password(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return json_error(type='field', field='password', description="error_1"), 200
    return None

def verify_alias(alias):
    if len(alias) < MIN_ALIAS_LENGTH:
        return json_error(type='field', field='alias', description='error_1'), 200
    if not re.match(ALIAS_MATCH_REGEX, alias):
        return json_error(type='field', field='alias', description='error_2'), 200
    if re.match('.*__.*', alias) or re.match('.*--.*', alias) or re.match('.*\.\..*', alias):
        return json_error(type='field', field='alias', description='error_3'), 200
    if db.schedules.find_one({'alias': alias}) is not None:
        return json_error(type='field', field='alias', description='error_4'), 200
    return None

def json_error(type, field=None, description=None):
    result = {'result': 'error', 'type': type}
    if field is not None:
        result['field'] = field
    if description is not None:
        result['description'] = description
    return jsonify(result)


def json_success(data=None):
    result = {'result': 'success'}
    if data is not None:
        result['data'] = data
    return jsonify(result)
