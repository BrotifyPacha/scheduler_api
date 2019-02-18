from os import urandom
from base64 import urlsafe_b64encode
from bson.objectid import ObjectId

def gen_schedule_alias():
    return urlsafe_b64encode(urandom(6)).decode('utf-8')

def get_mock_db():
    db = {
        'schedules': [
            {
                '_id': ObjectId('aaaaaaaaaaaaaaaaaaaaaaaa'),
                'alias': 'top_schedule',
                'availability': 'public',
                'first_day': '01.09.18',
                'creator': ObjectId('aaaaaaaaaaaaaaaaaaaaaaaa'),
                'moderators': [],
                'invited_users': [],
                'subscribed_users': [ObjectId('aaaaaaaaaaaaaaaaaaaaaaaa')],
                'schedule': [
                    [
                        ['','','','','','Обеспечение проектной деятельностью','Маркетинг'],
                        [],
                        ['','','','','','Обеспечение проектной деятельностью','Физ-ра'],
                        [],
                        [],
                        ['','','','','','Английский','Маркетинг'],
                        [],
                    ]
                ],
                'changes': []
            },
            {}
        ],
        'users':[
            {
                '_id': ObjectId('aaaaaaaaaaaaaaaaaaaaaaaa'),
                'username':'brotifypacha',
                'password':'2f5aabb4c4e3a44f9d557ea46c73b1311840f9aeeaa626fd08b0376154fdef29e472f813fda3e110d1c09900f9d4df028626969bcd3d10faa739ee04d906922d',
                'salt':'/GOy1msboXIFIaS0hbmdm5Mco9KBE1PWn+xAoxkM//k=',
                'firebase_id':''
            }
        ]
    }

#def get_today_date_str():
#    return datetime.date.today().strftime('%d.%m.%y')

#Получить обьект даты из строки формата дд.мм.гг
#def get_date_from_str(str):
#    return datetime.datetime.strptime(str, '%d.%m.%y').date()