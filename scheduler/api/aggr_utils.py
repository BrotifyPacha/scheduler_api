from bson.objectid import ObjectId


def get_basic_schedule_aggregation():
    """ Возвращает базовую аггрегацию для работы с запросами эндпоинта расписания """
    aggregation = [
        {
            '$lookup': {
                'from': 'users',
                'localField': 'creator',
                'foreignField': '_id',
                'as': 'creator'
            }
        },
        {
            '$unwind': '$creator'
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
            '$lookup': {
                'from': 'users',
                'localField': 'moderators',
                'foreignField': '_id',
                'as': 'moderators'
            }
        },
        {
            '$lookup': {
                'from': 'users',
                'localField': 'invited_users',
                'foreignField': '_id',
                'as': 'invited_users'
            }
        },
        {
            '$project': {
                'subscribed_users.salt': 0,
                'subscribed_users.password': 0,
                'subscribed_users.firebase_id': 0,
                'moderators.salt': 0,
                'moderators.password': 0,
                'moderators.firebase_id': 0,
                'invited_users.salt': 0,
                'invited_users.password': 0,
                'invited_users.firebase_id': 0,
                'creator.salt': 0,
                'creator.password': 0,
                'creator.firebase_id': 0,
            }
        }
    ]
    return aggregation


def get_basic_user_aggregation():
    """ Возвращает базовую аггрегацию для работы с запросами эндпоинта пользователей """
    aggregation = [
        {
            '$lookup': {
                'from': 'schedules',
                'localField': '_id',
                'foreignField': 'subscribed_users',
                'as': 'schedules'
            }
        },
        {
            '$project': {
                'salt': 0,
                'password': 0,
                'firebase_id': 0,
                'schedules.first_day': 0,
                'schedules.creator': 0,
                'schedules.moderators': 0,
                'schedules.invited_users': 0,
                'schedules.subscribed_users': 0,
                'schedules.schedule': 0,
                'schedules.changes': 0
            }
        }
    ]
    return aggregation


def parse_match_stage(dict, field_wrapper):
    """ Преобразует аргумент запроса match_fields в синтаксис стадии match для MongoDB  """
    print(f'aggr_utils.parse_match_stage: dict = {dict}, wrapper = {field_wrapper}')
    match = {}
    for key in dict:
        if isinstance(dict[key], list):
            if field_wrapper:
                match['$or'] = [ {key: field_wrapper(field)} for field in dict[key]]
            else:
                match[key] = {'$in': dict[key]}
        elif isinstance(dict[key], str):
            if field_wrapper:
                match[key] = field_wrapper(dict[key])
            else:
                match[key] = dict[key]
    return match

def get_regex_wrapper(pre, post, options='i'):
    def func_regex_wrapper(value):
        return regex_wrapper(pre, post, value, options)
    return func_regex_wrapper
def regex_wrapper(pre, post, value='', options='i'):
    """ Помещает значение value между значениями pre и post, внутри конструкции regex для MongoDB """
    return {'$regex': f'{str(pre)}{str(value)}{str(post)}', '$options': str(options)}


def whitelist_arr(whitelist, arr):
    """
    Перебирает поля словоря или списка, и для списка оставляет лишь записи которые присутствуют в списке whitelist,
    а для словаря осталвляет лишь записи с ключами присутствующими в списке whitelist
    """
    result = None
    if isinstance(arr, list):
        result = []
        for item in arr:
            if item in whitelist:
                result.append(item)
    elif isinstance(arr, dict):
        result = {}
        for key, value in iter(arr.items()):
            if key in whitelist:
                result[key] = value
    return result

def return_only_visible(user, schedules):
    shown_schedules = []
    for schedule in schedules:
        if schedule['availability'] == 'public':
            shown_schedules.append(schedule)
        if user is None:
            continue
        for user_schedule in user['schedules']:
            if user_schedule['_id'] == schedule['_id']:
                shown_schedules.append(schedule)
                break
    return shown_schedules


def objectid_to_str(input):
    """ Проходится по всему древу input и заменяет все ObjectId() на str(ObjectId) """
    if isinstance(input, list):
        result = []
        for item in input:
            result.append(objectid_to_str(item))
        input = result
    elif isinstance(input, dict):
        for key in input:
            input[key] = objectid_to_str(input[key])
    elif isinstance(input, ObjectId):
        input = str(input)
    return input


def limit(limit, list):
    """ Удаляет элементы списка list c конца так, чтобы кол-во элементов стало равным limit """
    while len(list) > limit:
        if len(list) == 0:
            break
        list.pop()
    return list


def skip(skip, list):
    """ Удаляет первые skip элементы списка list """
    for i in range(skip):
        if len(list) == 0:
            break
        list.pop(0)
    return list
