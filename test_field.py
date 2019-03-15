import pymongo
import pytz
import pprint

client = pymongo.MongoClient("mongodb+srv://dbadmin:dbadminpassword@schedulercluster-3xudq.gcp.mongodb.net/dbadmin")
db = client.scheduler_db

result = db.schedules.aggregate([
    {
        '$match':{
            'alias':'top-406'
        }
    },
    {
        '$lookup':{
            'from': 'users',
            'localField': 'subscribed_users',
            'foreignField': '_id',
            'as': 'subscribed_users'
        }
    },
    {
        '$project':{
            'subscribed_users.firebase_id':0,
            'subscribed_users.salt':0,
            'subscribed_users.password':0
        }
    },

])

for item in result:
    print(pprint.pformat(item))