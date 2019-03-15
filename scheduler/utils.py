from os import urandom
from base64 import urlsafe_b64encode
from bson.objectid import ObjectId
import datetime

def gen_schedule_alias():
    return urlsafe_b64encode(urandom(6)).decode('utf-8')

def long_to_date_str(long):
    return datetime.datetime.fromtimestamp(long).strftime('%d.%m.%y')

def date_in_millis(date_str):
    numbers = date_str.split('.')
    day = int(numbers[0])
    month = int(numbers[1])
    year = int(numbers[2])+2000
    date = datetime.datetime(year=year, month=month, day=day, hour=0, minute=0, second=0, microsecond=0)
    return date.timestamp()*1000

#Получить обьект даты из строки формата дд.мм.гг
#def get_date_from_str(str):
#    return datetime.datetime.strptime(str, '%d.%m.%y').date()


