import pymongo

client = pymongo.MongoClient("mongodb+srv://dbadmin:dbadminpassword@schedulercluster-3xudq.gcp.mongodb.net/dbadmin")
db = client.scheduler_db

def testfunc():
    return 'a','b'

print(testfunc())