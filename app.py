from flask import Flask, jsonify, request, make_response
import jwt
import datetime
import pymongo
from functools import wraps

app = Flask(__name__)
client = pymongo.MongoClient("mongodb+srv://m001-student:m001-mongodb-basics@sandbox.ymprapn.mongodb.net/test")
db = client.flask
logs = db.logins
app.config['SECRET_KEY'] = 'thisisthesecret'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers['token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message' : 'Token is invalid'}), 403

        return f(*args, **kwargs)
    return decorated

@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'Anyone can view this!'})

@app.route('/protected',methods=['POST'])
@token_required
def protected():
    return jsonify({'message' : 'This is only available for people with valid tokens.'})

@app.route('/register')
def register():
    auth = request.authorization

    if auth and auth.password:
        token = jwt.encode({'user': auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'],algorithm="HS256")
        print(token)
        logs.insert_one({'user': auth.username, 'password': auth.password, 'token': token})
        return jsonify({'token' : jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])})
    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password:
        x = logs.find_one({'user':auth.username})

        try:
            if x['user'] == auth.username and x['password'] == auth.password:
                token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},app.config['SECRET_KEY'], algorithm="HS256")
                myquery = {'user': auth.username}
                newvalues = {"$set": {"token": token}}
                logs.update_one(myquery, newvalues)
            return token
            return jsonify({'token': jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])})
        except:
            return make_response('Wrong username and password', 401,{'WWW-Authenticate': 'Basic realm="Login Required"'})
    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


@app.route('/add', methods=['POST'])
@token_required
def add():
    a = request.values.get("a", type=int, default=None)
    b = request.values.get("b", type=int, default=None)
    s = a+b
    return jsonify(s)

@app.route('/div', methods=['POST'])
@token_required
def div():
    a = request.values.get("a", type=int, default=None)
    b = request.values.get("b", type=int, default=None)
    div = a/b
    return jsonify(div)

@app.route('/sub', methods=['POST'])
@token_required
def sub():
    a = request.values.get("a", type=int, default=None)
    b = request.values.get("b", type=int, default=None)
    d = a-b
    return jsonify(d)

@app.route('/mult', methods=['POST'])
@token_required
def mult():
    a = request.values.get("a", type=int, default=None)
    b = request.values.get("b", type=int, default=None)
    m = a*b
    return jsonify(m)



@app.route('/test')
@token_required
def test():
    return "Success"


if __name__ == '__main__':
    app.run(debug=True)
        