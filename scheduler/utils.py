from os import urandom
from base64 import urlsafe_b64encode

def gen_schedule_alias():
    return urlsafe_b64encode(urandom(6)).decode('utf-8')

