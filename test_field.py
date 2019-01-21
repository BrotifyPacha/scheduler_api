import pymongo

client = pymongo.MongoClient("mongodb+srv://dbadmin:dbadminpassword@schedulercluster-3xudq.gcp.mongodb.net/dbadmin")
db = client.scheduler_db

schedules = db.schedules.aggregate(
    [
        {
            '$lookup':{
                'from':'users',
                'localField': 'creator',
                'foreignField':'_id',
                'as':'creator'
            }
        },
        {
            '$unwind':'$creator'
        },
        {
            '$project':{
                'creator.password':0,
                'creator.salt':0,
                'creator.schedules':0,
                'firebase_id':0
            }
        }
    ])
for schedule in schedules:
    print(schedule)