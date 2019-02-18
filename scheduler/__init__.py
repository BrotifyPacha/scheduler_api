import pymongo
from flask import Flask

app = Flask(__name__)
app.secret_key = 'aeX2bjauRpkQZLrKD4hTYb0RgjkB3zBW6lJVH9FROTA='
app.jinja_env.lstrip_blocks = True
app.jinja_env.trim_blocks = True
#try:
db = pymongo.MongoClient("mongodb+srv://dbadmin:dbadminpassword@schedulercluster-3xudq.gcp.mongodb.net/dbadmin").scheduler_db
#except:
    #from scheduler.utils import get_mock_db
    #db = get_mock_db()

from scheduler.api.routes import api
app.register_blueprint(api)
from scheduler.web.routes import web
app.register_blueprint(web)