 from datetime import timedelta

import redis
from flask import Flask, jsonify, request, make_response
import pymongo
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

ACCESS_EXPIRES = timedelta(hours=1)

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "secretkeyenlacenturia"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
jwt = JWTManager(app)
client = pymongo.MongoClient("mongodb+srv://m001-student:m001-mongodb-basics@sandbox.ymprapn.mongodb.net/test")
db = client.flask
logs = db.logins

jwt_redis_blocklist = redis.StrictRedis(
    host="localhost", port=6379, db=0, decode_responses=True
)

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None

@app.route('/register')
def register():
    auth = request.authorization

    if auth and auth.password:
        logs.insert_one({'user': auth.username, 'password': auth.password})
        return jsonify(msg="User created")
    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password:
        x = logs.find_one({'user': auth.username})

        try:
            if x['user'] == auth.username and x['password'] == auth.password:
                access_token = create_access_token(identity=auth.username)
                return jsonify(access_token=access_token)
        except:
            return make_response('Wrong username and password', 401,{'WWW-Authenticate': 'Basic realm="Login Required"'})
    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.route("/logout", methods=["DELETE"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    print(jti)
    jwt_redis_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
    return jsonify(msg="Access token revoked")

@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'Anyone can view this!'})

@app.route('/protected',methods=['POST'])
@jwt_required()
def protected():
    return jsonify({'message' : 'This is only available for people with valid tokens.'})

@app.route('/add', methods=['POST'])
@jwt_required()
def add():
    a = request.values.get("a", type=int, default=None)
    b = request.values.get("b", type=int, default=None)
    s = a+b
    return jsonify(s)

@app.route('/div', methods=['POST'])
@jwt_required()
def div():
    a = request.values.get("a", type=int, default=None)
    b = request.values.get("b", type=int, default=None)
    div = a/b
    return jsonify(div)

@app.route('/sub', methods=['POST'])
@jwt_required()
def sub():
    a = request.values.get("a", type=int, default=None)
    b = request.values.get("b", type=int, default=None)
    d = a-b
    return jsonify(d)

@app.route('/mult', methods=['POST'])
@jwt_required()
def mult():
    a = request.values.get("a", type=int, default=None)
    b = request.values.get("b", type=int, default=None)
    m = a*b
    return jsonify(m)

if __name__ == '__main__':
    app.run(debug=True)
