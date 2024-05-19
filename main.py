import os
import uvicorn
import random
from fastapi import FastAPI
import boto3
import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode
from models.signin_user import SigninUser
from models.signup_user import SignupUser
from models.signup_confirm_user import SignupConfirmUser
from models.validate_token import Token
from models.admin_add_user import AdminAddUser

from fastapi import Header

app = FastAPI()

region = 'ap-south-1'
userpool_id = 'ap-south-1_YEH0sqfmB'
app_client_id = '4nql0ttol3en0nir4d56ctdc6i'
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)

with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']


def verifyToken(event):
    token = event['token']
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False

    # construct the public key
    public_key = jwk.construct(keys[key_index])

    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    print('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['aud'] != app_client_id:
        # print('Token was not issued for this audience')
        return False
    # now we can use the claims
    # print(claims)
    return claims


# password generator
def password_generator():
    password = ""
    for i in range(12):
        password += chr(random.randint(33, 126))
    return password


def signup_user(username, password, email):
    client = boto3.client('cognito-idp')
    password = password
    response = client.sign_up(
        ClientId=os.environ['COGNITO_CLIENT_ID'],
        Username=username,
        Password=password,
        UserAttributes=[
            {
                'Name': 'email',
                'Value': email
            },
        ]
    )
    return response


def login_user(username, password):
    client = boto3.client('cognito-idp')
    try:
        response = client.initiate_auth(
            ClientId=os.environ['COGNITO_CLIENT_ID'],
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
    except client.exceptions.NotAuthorizedException as e:
        response = {"message": "Not authorized"}
    except client.exceptions.UserNotFoundException as e:
        response = {"message": "User not found"}
    return response


def confirm_signup(username, password):
    client = boto3.client('cognito-idp')
    response = client.confirm_sign_up(
        ClientId=os.environ['COGNITO_CLIENT_ID'],
        Username=username,
        ConfirmationCode=password,
    )
    return response


@app.post("/signup")
async def signup(user: SignupUser):
    response = signup_user(user.email, user.password, user.email)
    return response


@app.post("/confirm_signup")
async def confirm_signup(user: SignupConfirmUser):
    response = confirm_signup(user.username, user.confirmation_code)
    return response


@app.post("/login")
async def login(user: SigninUser):
    response = login_user(user.username, user.password)
    return response


@app.post("/validate_token")
async def validate_token(token: Token):
    # decode token
    claims = verifyToken({"token": token.token})
    return claims


@app.get("/usergroups/")
async def usergroups(token: str = Header(None)):
    usergroups = lambda token: verifyToken({"token": token})['cognito:groups']
    return usergroups(token)


@app.post("/add_user")
async def add_user(user: AdminAddUser):
    client = boto3.client('cognito-idp')
    response = client.admin_create_user(
        UserPoolId=os.environ['COGNITO_USER_POOL_ID'],
        Username=user.username,
        TemporaryPassword=password_generator(),
        UserAttributes=[
            {
                'Name': 'email',
                'Value': user.email
            },
        ]
    )
    return response


if __name__ == "__main__":
    uvicorn.run(app, port=8000)
