from flask import Flask, request, jsonify, make_response
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from datetime import datetime
import pandas as pd
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'Asd_sda_zxs_d'
db = SQLAlchemy(app)


class vessel_data(db.Model):
    __tablename__ = "vessel_data"

    id = db.Column(db.Integer, primary_key=True)
    vessel_names = db.Column(db.String(30), nullable = False)
    volume = db.Column(db.Integer, nullable= False)
    product = db.Column(db.String(30),nullable=True)
    group = db.Column(db.String(30), nullable = False)
    family = db.Column(db.String(30),nullable = False)
    start_date = db.Column(db.Date,nullable=False)
    end_date = db.Column(db.Date)
    origin = db.Column(db.String(30),nullable = False)
    destination = db.Column(db.String(30))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    family = db.Column(db.String(30))

def add_to_db(): #runs once.
    file_name = 'vessel_data.csv'
    df = pd.read_csv(file_name,sep=';')
    df.to_sql(con= db.engine,index_label='id',name=vessel_data.__tablename__, if_exists='replace')
    db.create_all() #run it at the first time only


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms="HS256")

            current_user = User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


signup_arg = reqparse.RequestParser()
signup_arg.add_argument("id", type=int, help="ID is required", required=True)
signup_arg.add_argument("username", type=str, help="Username is required", required=True)
signup_arg.add_argument("password", type=str, help="password is required", required=True)
signup_arg.add_argument("family", type=str, help="Family type is required", required=True)

@app.route('/register', methods=['GET', 'POST'])
def signup_user():

    data = signup_arg.parse_args()
    hashed_password = generate_password_hash(data["password"], method='sha256')
    result = User.query.filter_by(id=data['id']).first()
    if result:
        abort(409, message= "id taken...")

    new_user = User(id = data['id'],public_id=str(uuid.uuid4()), name=data["username"], password=hashed_password, family=data["family"])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


login_arg = reqparse.RequestParser()
login_arg.add_argument("username", type=str, help="Username is required", required=True)
login_arg.add_argument("password", type=str, help="password is required", required=True)


@app.route('/login')
def login():
    #auth = request.authorization #working from web.
    data = login_arg.parse_args()

    #if not auth or not auth.username or not auth.password:
        #return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=data['username']).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, data['password']):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'],algorithm="HS256")

        return {'token' : token}

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/users', methods=['GET'])

def get_all_users():
   users = User.query.all()

   result = []

   for user in users:
       user_data = {}
       user_data['public_id'] = user.public_id
       user_data['name'] = user.name
       user_data['password'] = user.password
       user_data['family'] = user.family

       result.append(user_data)

   return {'users': result}


resource_fields = {
    'id' : fields.Integer,
    'vessel_names' : fields.String,
    'volume' : fields.String,
    'product' : fields.String,
    'group' : fields.String,
    'family' : fields.String,
    'start_date' :  fields.String,
    'end_date' : fields.String,
    'origin' :fields.String,
    'destination' : fields.String
}







@app.route('/vessels_family',methods=['GET'])
@token_required
def get_all_vessels(current_user):
    big_results= []
    results = vessel_data.query.filter_by(family = current_user.family).all()
    for result in results:
        data = {}
        data['id'] = result.id
        data['vessel_names'] = result.vessel_names
        data['volume'] = result.volume
        data['product'] = result.product
        data['group'] = result.group
        data['family'] = result.family
        data['start_date'] =  result.start_date
        data['end_date'] = result.end_date
        data['origin'] = result.origin
        data['destination'] = result.destination

        big_results.append(data)

    if not big_results:
        abort(404,message = "Vessel data not found")

    #print(big_results)
    return jsonify({"The no of barrles is " : big_results})


@app.route('/family_volume',methods=['GET'])
@token_required
def get_volume(current_user):
    results = vessel_data.query.filter_by(family = current_user.family).all()
    total_volume = 0
    for row in results:
        total_volume += row.volume

    return jsonify({"The Total amount of volume " : total_volume})


Trades_arg = reqparse.RequestParser()
Trades_arg.add_argument("vessel_names", type=str, help="Name of the Vessel required", required=True)


class Trades(Resource):

    @marshal_with(resource_fields)
    def get(self):
        auth = Trades_arg.parse_args()
        result = vessel_data.query.filter_by(vessel_names =auth["vessel_names"]).all()
        if not result:
            abort(404,message = "Vessel data not found")
        return result





No_barrels_arg = reqparse.RequestParser()
No_barrels_arg.add_argument("origin", type=str, help="Name of the first country required", required=True)
No_barrels_arg.add_argument("destination", type=str, help="Name of the second country required", required=True)


class No_barrels(Resource):

    def get(self):
        args = No_barrels_arg.parse_args()
        result1 = vessel_data.query.filter_by(origin = args['origin'],destination = args['destination']).count()
        result2 = vessel_data.query.filter_by(origin = args['destination'] ,destination = args['origin']).count()
        result = result1+result2
        return jsonify({"The no of barrles is " : result})

api.add_resource(Trades, "/Trades/")
api.add_resource(No_barrels,"/No_barrels/")

if __name__ == "__main__":

    #Run it to create the database the first time only
    #add_to_db()



    app.run(debug=True)
