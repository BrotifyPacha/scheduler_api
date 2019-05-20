from os import urandom
from base64 import urlsafe_b64encode
import datetime


def gen_schedule_alias():
    return urlsafe_b64encode(urandom(6)).decode('utf-8')


def date_in_millis(date_str):
    numbers = date_str.split('.')
    day = int(numbers[0])
    month = int(numbers[1])
    year = int(numbers[2])+2000
    date = datetime.datetime(year=year, month=month, day=day, hour=0, minute=0, second=0, microsecond=0)
    return date.timestamp()*1000

