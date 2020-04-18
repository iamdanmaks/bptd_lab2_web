from flask import Flask
from flask_cors import CORS


app = Flask(__name__)
app.config.update(
    SECRET_KEY='really_big_secret'
)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
user_data = {}
messages = []
keys = [None, None]


from app import routes, utils
