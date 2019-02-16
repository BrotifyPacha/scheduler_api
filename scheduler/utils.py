from os import urandom
from base64 import urlsafe_b64encode
import datetime
##import pytz

def gen_schedule_alias():
    return urlsafe_b64encode(urandom(6)).decode('utf-8')

#def get_today_date_str():
#    return datetime.date.today().strftime('%d.%m.%y')

#Получить обьект даты из строки формата дд.мм.гг
#def get_date_from_str(str):
#    return datetime.datetime.strptime(str, '%d.%m.%y').date()