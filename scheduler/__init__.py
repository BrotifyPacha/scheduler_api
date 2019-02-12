import pymongo
from flask import Flask

app = Flask(__name__)
app.secret_key = 'aeX2bjauRpkQZLrKD4hTYb0RgjkB3zBW6lJVH9FROTA='
app.jinja_env.lstrip_blocks = True
app.jinja_env.trim_blocks = True
db = pymongo.MongoClient("mongodb+srv://dbadmin:dbadminpassword@schedulercluster-3xudq.gcp.mongodb.net/dbadmin").scheduler_db

from scheduler import api_routes, web_routes