from __future__ import annotations
import json
import math
import os
import random
import traceback
import jwt
from fastapi.security import HTTPBearer
from urllib.parse import urlencode
from common.services.email_service import EmailHandler
from common.services.jwt_decoder import validate
auth_scheme = HTTPBearer()
from common.log_data import ApplicationLogger as applog
from common.messages import Messages
from fastapi import APIRouter, Request, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from model.core.models import Users, Organization
import requests
import datetime
user_router = APIRouter(
    prefix='/user'
)

@user_router.post('/login')
async def login(request: Request):
    try:
        header = request.headers
        data = await request.json()
        email = data.get("email")
        password = data.get("password")
        if password and email  :
            user = Users.select().where(Users.email == email).first()
            if user:
                org_name = user.organization
                hash_password = Users.hash_password(password)
                user_password = user.password
                if hash_password==user_password:
                    payload = {
                        "email": email,
                        "organization": org_name,
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    }
                    secret_key = os.getenv("SECRET_KEY")
                    # Generate the access token
                    access_token = jwt.encode(payload, secret_key, algorithm='HS256')
                    query = Users.update(access_token=access_token).where(Users.email == email)
                    updated_rows = query.execute()
                    response_data = {"email": email,
                                     "organization": org_name,
                                     "access_token": access_token}
                    # Users.create(**datadict)
                    return JSONResponse(status_code=200,
                                        content={"code": 200, "message": "OK", "data": response_data})
            return JSONResponse(status_code=401,
                                content={"code": 401,
                                         "message": "Unauthorized user"})
        else:
            applog.error(f"| {data} | Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post('/signup')
async def signup(request: Request):
    try:
        header = request.headers
        data = await request.json()
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        email = data.get("email")
        password = data.get("password")
        org_name = data.get("organization")
        if first_name and last_name and password and email and org_name:
            organization = Organization.select().where(Organization.name == org_name).first()
            if organization is None:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Unauthorized user"})
            payload = {
                "email": email,
                "organization" : org_name,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }
            user = Users.select().where(Users.email == email).first()
            if user:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "User Already Registerd"})
            # Define the secret key
            secret_key = os.getenv("SECRET_KEY")

            # Generate the access token
            access_token = jwt.encode(payload, secret_key, algorithm='HS256')
            user = Users(user_first_name=first_name, user_last_name=last_name, email=email,
                         organization=org_name,role="operator",access_token=access_token,
                         )
            user.set_password(password)  # Hashes the password and stores it
            user.save()
            response_data={"email": email,
                           "organization" : org_name,
                           "access_token":access_token}
            # Users.create(**datadict)
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "OK", "data": response_data})
        else:
            applog.error(f"| {data} | Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post('/ssosignup')
async def ssosignup(request: Request):
    try:
        header = request.headers
        data = await request.json()
        auth_code = data.get("authorization_code")
        if auth_code:
            REDIRECT_URI = os.getenv("REDIRECT_URI")
            CLIENT_ID = os.getenv("CLIENT_ID")
            CLIENT_SECRET = os.getenv("CLIENT_SECRET")
            token_params = {
                'code':auth_code,
                'client_id': CLIENT_ID,
                'client_secret' : CLIENT_SECRET,
                'redirect_uri' : REDIRECT_URI,
                'grant_type' : 'authorization_code'
            }
            token_url = Messages.TOKEN_URL
            token_response = requests.post(token_url,data=token_params)
            token_data = json.loads(token_response.text)
            access_token = None
            refresh_token = None
            if "access_token" in token_data:
                access_token = token_data.get("access_token")
            if "refresh_token" in token_data:
                refresh_token = token_data.get("refresh_token")
            people_api_url = Messages.PEOPLE_API_URL
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept' : 'application/json'
            }
            user_data = None
            params = {
                'personFields': 'names,photos,emailAddresses,phoneNumbers,organizations',
            }

            if access_token:
                response = requests.get(people_api_url,headers= headers,params=params)
                user_data = response.json()
            else:
                applog.error(" Api execution failed with 400 status code ")
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Invalid Payload"})
            display_name = ""
            email_address = ""
            if "names" in user_data:
                display_name = user_data.get("names")[0].get("displayName")
            if "emailAddresses" in user_data:
                email_address = user_data.get("emailAddresses")[0].get("value")
            firstname,lastname = (display_name.split()[0] , display_name.split()[1])
            organization = email_address.split('@')[1].split(".")[0]
            user = Users.select().where(Users.email == email_address).first()
            if user:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "User Already Registerd"})
            organization = Organization.select().where(Organization.name==organization).first()
            if organization is None:
                return JSONResponse(status_code=401,
                                    content={"code": 401,
                                             "message": "Unauthorized user"})
            user = Users(user_first_name=firstname, user_last_name=lastname, email=email_address,
                         organization=organization.name,role="operator",access_token=access_token,
                         refresh_token=refresh_token)
            user.save()
            response_data = {
                "access_token":access_token,
                "display_name":display_name,
                "email":email_address
            }
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "OK", "data": response_data})
        else:
            applog.error(f"| {data} | Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.get('/oauth')
async def sso(request: Request):
    try:
        auth_code = request.query_params.get('code')
        if auth_code:
            applog.info(f"auth code is {auth_code}")
            # Users.create(**datadict)
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "OK", "data": auth_code})
        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.get('/get_sso_url')
async def get_sso_url(request: Request):
    try:
        REDIRECT_URI = os.getenv("REDIRECT_URI")
        CLIENT_ID = os.getenv("CLIENT_ID")
        scope = Messages.SCOPE
        auth_params = {
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': f'{scope}',
            'response_type': 'code',
            'access_type': 'offline'

        }
        authorize_url = Messages.AUTHORIZATION_URL
        auth_url = f'{authorize_url}?{urlencode(auth_params)}'
        return JSONResponse(status_code=200,
                            content={"code": 200, "message": "OK", "data": auth_url})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post('/validate_token')
async def validate_token(request: Request):
    try:
        headers = request.headers
        data = await request.json()
        access_token = data.get("access_token")
        email,organization = validate(headers)
        if access_token and email:
            user = Users.select().where(Users.email == email).first()
            if user and user.access_token == access_token:
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "User Authorized", "data": access_token})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Invalid Token"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post('/ssologin')
async def ssologin(request: Request):
    try:
        header = request.headers
        data = await request.json()
        auth_code = data.get("authorization_code")
        if auth_code:
            REDIRECT_URI = os.getenv("REDIRECT_URI")
            CLIENT_ID = os.getenv("CLIENT_ID")
            CLIENT_SECRET = os.getenv("CLIENT_SECRET")
            token_params = {
                'code':auth_code,
                'client_id': CLIENT_ID,
                'client_secret' : CLIENT_SECRET,
                'redirect_uri' : REDIRECT_URI,
                'grant_type' : 'authorization_code'
            }
            token_url = Messages.TOKEN_URL
            token_response = requests.post(token_url,data=token_params)
            token_data = json.loads(token_response.text)
            access_token = None
            refresh_token = None
            if "access_token" in token_data:
                access_token = token_data.get("access_token")
            if "refresh_token" in token_data:
                refresh_token = token_data.get("refresh_token")
            people_api_url = Messages.PEOPLE_API_URL
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept' : 'application/json'
            }
            user_data = None
            params = {
                'personFields': 'names,photos,emailAddresses,phoneNumbers,organizations',
            }

            if access_token:
                response = requests.get(people_api_url,headers= headers,params=params)
                user_data = response.json()
            else:
                applog.error(" Api execution failed with 400 status code ")
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Invalid Payload"})
            email_address = ""
            if "emailAddresses" in user_data:
                email_address = user_data.get("emailAddresses")[0].get("value")
            organization = email_address.split('@')[1].split(".")[0]
            user = Users.select().where((Users.email == email_address) & (Users.organization == organization)).first()
            if user:
                query = Users.update(access_token=access_token).where(Users.email == email_address)
                updated_rows = query.execute()
                response_data = {
                    "access_token": access_token,
                    "email": email_address
                }
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OK", "data": response_data})

            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Unauthorized User"})
        else:
            applog.error(f"| {data} | Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post("/forgot_password")
async def forgot_password(request : Request):
    try:
        data = await request.json()
        email = data.get("email")
        new_password = data.get("new_password")
        otp = data.get("otp")
        if email and new_password and otp:
            user = Users.select().where(Users.email == email).first()
            if user and user.otp==otp:
                new_password = Users.hash_password(new_password)
                query = Users.update(password=new_password).where(Users.email == email)
                updated_rows = query.execute()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "Password Changed", "data": ""})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Invalid otp"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass


@user_router.post('/send_otp')
async def send_otp(request: Request):
    try:
        data = await request.json()
        email = data.get("email")
        if email:
            user = Users.select().where(Users.email == email).first()
            if user:
                digits = [i for i in range(0, 10)]
                ## initializing a string
                random_str = ""
                ## we can generate any lenght of string we want
                for i in range(6):
                    index = math.floor(random.random() * 10)
                    random_str += str(digits[index])
                handler = EmailHandler()
                handler.send_email(email,f"OTP iS {random_str}")
                query = Users.update(otp=random_str).where(Users.email == email)
                updated_rows = query.execute()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OTP SENT", "data": email})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Invalid Token"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post('/enable_mfa')
async def enable_mfa(request: Request):
    try:
        headers = request.headers
        data = await request.json()
        access_token = data.get("access_token")
        email,organization = validate(headers)
        if email and access_token:
            user = Users.select().where(Users.email == email).first()
            if user and user.access_token==access_token:
                query = Users.update(mfa=True).where(Users.email == email)
                updated_rows = query.execute()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "MFA Enabled", "data": ""})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Unauthorized User"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post('/change_password')
async def change_password(request: Request):
    try:
        data = await request.json()
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        email = data.get("email")
        if email and current_password and new_password:
            user = Users.select().where(Users.email == email).first()
            if user:
                hash_password = Users.hash_password(current_password)
                user_password = user.password
                if hash_password == user_password:
                    new_password = Users.hash_password(new_password)
                    query = Users.update(password = new_password).where(Users.email == email)
                    updated_rows = query.execute()
                    return JSONResponse(status_code=200,
                                        content={"code": 200, "message": "Password Changed", "data": ""})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Unauthorized User"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post('/add_organization_domain')
async def add_organization(request: Request):
    try:
        data = await request.json()
        name = data.get("name")
        website = data.get("website")
        details = data.get("details")
        if name and website and details:
            organization = Organization.select().where(Organization.name == name).first()
            if organization:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Already Present"})
            else:
                org = Organization(name=name,website=website,details=details)
                org.save()
                return JSONResponse(status_code=200,
                                    content={"code": 200,
                                             "message": "Organization added"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass