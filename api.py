from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, create_refresh_token, jwt_refresh_token_required, get_raw_jwt, get_current_user
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import datetime

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ApiDatabase.db'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)
db = SQLAlchemy(app)

blacklist = set()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    token_type = expired_token['type']

    username = get_jwt_identity()

    data = {
            'refresh_token': create_refresh_token(identity=username)
    }
    return jsonify({
        'status': 401,
        'msg': 'The {} token has expired'.format(token_type)
    }), 401

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist

@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()

    hash_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hash_password, admin=False)

    db.session.add(new_user)
    db.session.commit()

    user_data = {}
    user_data['public_id'] = new_user.public_id
    user_data['name'] = new_user.name

    return jsonify({'data':user_data, 'message': 'New user created successfully!'}), 200

@app.route('/get_all_user', methods=['GET'])
@jwt_required
def get_all_users():

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users':output})

@app.route('/user/<public_id>', methods=['GET'])
@jwt_required
def get_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()
    
    if not user:
        return jsonify({'message':'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin

    return jsonify({'users':user_data})

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'message':'Username OR Password is required.'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return jsonify({'message' : 'User is not defined!'})

    expires = datetime.timedelta(minutes=2)

    if check_password_hash(user.password, auth.password):
        data = {
        'access_token' : create_access_token(identity=user.name, expires_delta=expires),
        # 'refresh_token': create_refresh_token(identity=user.name)
        }
        return jsonify({'Username':user.name, 'token':data}), 200
    return jsonify({'message':'Something went wrong!'})

@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200

@app.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200

if __name__ == '__main__':
    app.run(debug=True)