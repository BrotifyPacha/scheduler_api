from hashlib import sha3_512
from os import urandom
from base64 import b64encode
import jwt
from bson.objectid import ObjectId
from flask import session, request
import functools

from scheduler import db
secret = 'aeX2bjauRpkQZLrKD4hTYb0RgjkB3zBW6lJVH9FROTA='


def authenticate():
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            user = get_user_from_session(session)
            if user is None:
                user = get_user_from_header(request)
                if user is None:
                    return func(*args, **kwargs)
            return func(*args, **kwargs, user=user)
        return wrapper
    return decorator


def hash_password_and_salt(password, salt):
    salted_password = (password+salt).encode('UTF-8')
    return sha3_512(salted_password).hexdigest()

print(hash_password_and_salt('2', 'ZM6+d2Knq/eZ1Vfu0o5lGw/cpFhAB4Q3BMcz493ir04='))

def gen_salt():
    return b64encode(urandom(32)).decode('UTF-8')


def check_password(password, salt, password_hash):
    return hash_password_and_salt(password, salt) == password_hash


# если всё прошло успешно возвращает user_id, в противном случае None
def get_user_from_header(request):
    if 'Authorization' not in request.headers:
        return None
    auth_token = request.headers['Authorization']
    try:
        user_id = jwt.decode(auth_token, secret, verify=True, algorithms=['HS512'])['user_id']
    except:
        return None
    user = db.users.find_one({'_id': ObjectId(user_id)})
    return user

def get_user_from_session(session):
    if 'token' not in session:
        return None
    user_id = check_token(session['token'])
    user = db.users.find_one({'_id': ObjectId(user_id)})
    return user


def check_token(token):
    try:
        user_id = jwt.decode(token, secret, algorithms=['HS512'])['user_id']
    except:
        return None
    if token != gen_signed_token(user_id):
        return None
    user = db.users.find_one({'_id': ObjectId(user_id)})
    if user is None:
        return None
    return user_id

def gen_signed_token(user_id):
    return jwt.encode({'user_id':user_id}, secret, algorithm='HS512').decode('utf-8')

