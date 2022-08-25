import email
from flask import Blueprint,jsonify ,request,Flask
from werkzeug.security import  check_password_hash,generate_password_hash
import  validators
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT
from src.database import User,db

########### jwt authentication ###################################
from flask_jwt_extended import create_access_token, create_refresh_token,jwt_required,get_jwt_identity
from flasgger import swag_from
################### end ###########################################



projectapp=Blueprint("app",__name__,url_prefix="/api/v1/projectapp")





# both method of definig below is same we are use any one
# @app.route('/', methods=['GET'])
# @projectapp.get("/")
# def index():
#     return {"hello": "this is ashutosh singh"}

# @projectapp.get("/hello")
# def Hello():
#     return jsonify({"hello": "this is ashutosh singh"})

# given above fuction gives result same 


@projectapp.post('/register')
@swag_from('./docs/app/register.yaml')
def register():
    username=request.json['username']
    email=request.json['email']
    password=request.json['password']
    if len(password)<6:
        return jsonify({"error":" password should we max 6 digits"}),HTTP_400_BAD_REQUEST
    if len(username)<3:
        return jsonify({"error":"username to short"}),HTTP_400_BAD_REQUEST
    if not username.isalnum() <3:
        return jsonify({"error":"username should be alphanumeric,also no space"}),HTTP_400_BAD_REQUEST
    if not validators.email(email):
        return jsonify({"error":"Email is not valid"}),HTTP_400_BAD_REQUEST
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({'error': "Email is taken"}),HTTP_409_CONFLICT
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error': "username is taken"}), HTTP_409_CONFLICT

    pwd_hash=generate_password_hash(password)
    user=User(username=username,password=pwd_hash,email=email)
    db.session.add(user)
    db.session.commit()
    return jsonify({
        "message":"user created",
        "user":{
            'username':username,'email':email
        },
    }),HTTP_201_CREATED





@projectapp.post('/login')
# here we are give yml file path
@swag_from('./docs/app/login.yaml')
def login():
    email = request.json.get('email', '')
    password = request.json.get('password', '')

    user = User.query.filter_by(email=email).first()

    if user:
        is_pass_correct = check_password_hash(user.password, password)

        if is_pass_correct:
            refresh = create_refresh_token(identity=user.id)
            access = create_access_token(identity=user.id)

            return jsonify({
                'user': {
                    'refresh': refresh,
                    'access': access,
                    'username': user.username,
                    'email': user.email
                }

            }), HTTP_200_OK

    return jsonify({'error': 'Wrong credentials'}), HTTP_401_UNAUTHORIZED




@projectapp.get("/me")
@jwt_required()
def me():
    user_id = get_jwt_identity()
    # get_jwt_identity return user id which user send 
    # request with token becuse be create token user id
    user = User.query.filter_by(id=user_id).first()
    return jsonify({
        'username': user.username,
        'email': user.email
    }), HTTP_200_OK



# here we are genrate access token using refersh token
@projectapp.get('/token/refresh')
@jwt_required(refresh=True)
@swag_from('./docs/app/getrefreshtoken.yaml')
def refresh_users_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)

    return jsonify({
        'access': access
    }), HTTP_200_OK



