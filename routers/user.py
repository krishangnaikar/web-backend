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
from common.services.authentictor import generate_mfa_uri,validate_otp
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
        if password and email:
            user = Users.select().where(Users.email == email).first()
            if user:
                org_name = user.organization_name
                hash_password = Users.hash_password(password)
                user_password = user.password
                if hash_password==user_password:
                    if user.mfa and user.mfa_type=="email":
                        digits = [i for i in range(0, 10)]
                        ## initializing a string
                        random_str = ""
                        ## we can generate any lenght of string we want
                        for i in range(6):
                            index = math.floor(random.random() * 10)
                            random_str += str(digits[index])
                        handler = EmailHandler()
                        handler.send_mfa_otp_email(email,random_str)
                        query = Users.update(otp=random_str,otp_expiry = datetime.datetime.now() + datetime.timedelta(seconds = 300)).where(Users.email == email)
                        updated_rows = query.execute()
                        return JSONResponse(status_code=200,
                                            content={"code": 200, "message": "OTP SENT", "data": "email"})
                    if user.mfa and user.mfa_type=="authenticator" and user.mfa_verified:
                        return JSONResponse(status_code=200,
                                            content={"code": 200, "message": "OTP SENT", "data": "authenticator"})
                    payload = {
                        "email": email,
                        "organization": org_name,
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=int(os.getenv("TOKEN_EXPIRY")))
                    }
                    secret_key = os.getenv("SECRET_KEY")
                    # Generate the access token
                    access_token = jwt.encode(payload, secret_key, algorithm='HS256')
                    query = Users.update(access_token=access_token).where(Users.email == email)
                    updated_rows = query.execute()
                    response_data = {"email": email,
                                     "organization": org_name,
                                     "access_token": access_token,
                                     "display_name":user.user_first_name + " "+ user.user_last_name,
                                     "role":user.role}
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

@user_router.post('/mfa_login')
async def mfa_login(request: Request):
    try:
        header = request.headers
        data = await request.json()
        email = data.get("email")
        otp = data.get("otp")
        if otp and email:
            user = Users.select().where(Users.email == email).first()
            if user and user.mfa:
                mfa_type = user.mfa_type
                secret_key = user.mfa_secret
                org_name = user.organization_name
                store_otp = ""
                if mfa_type=="email":
                    store_otp = user.otp
                    if user.otp_expiry < datetime.datetime.now():
                        store_otp = ""
                if mfa_type=="authenticator":
                    store_otp = validate_otp(otp,secret_key)
                if store_otp==otp:
                    payload = {
                        "email": email,
                        "organization": org_name,
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=int(os.getenv("TOKEN_EXPIRY")))
                    }
                    secret_key = os.getenv("SECRET_KEY")
                    # Generate the access token
                    access_token = jwt.encode(payload, secret_key, algorithm='HS256')
                    query = Users.update(access_token=access_token,otp="").where(Users.email == email)
                    updated_rows = query.execute()
                    response_data = {"email": email,
                                     "organization": org_name,
                                     "access_token": access_token,
                                     "display_name":user.user_first_name + " " + user.user_last_name,
                                     "role":user.role}
                    # Users.create(**datadict)
                    return JSONResponse(status_code=200,
                                        content={"code": 200, "message": "OK", "data": response_data})
                else:
                    return JSONResponse(status_code=400,
                                        content={"code": 400,
                                                 "message": "Invalid OTP"})
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
                return JSONResponse(status_code=401,
                                    content={"code": 401,
                                             "message": "Unauthorized user"})
            payload = {
                "email": email,
                "organization" : org_name,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=int(os.getenv("TOKEN_EXPIRY")))
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
                         organization_name=org_name,role="operator",access_token=access_token,organization_id=organization.id
                         )
            user.set_password(password)  # Hashes the password and stores it
            user.save()
            handler = EmailHandler()
            handler.send_email_validation(email, access_token)
            response_data = {"email": email,
                           "organization" : org_name,
                           "access_token":access_token,"role":"operator"}
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
            payload = {
                "email": email_address,
                "organization": organization.name,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=int(os.getenv("TOKEN_EXPIRY")))
            }
            # Define the secret key
            secret_key = os.getenv("SECRET_KEY")

            # Generate the access token
            access_token = jwt.encode(payload, secret_key, algorithm='HS256')
            user = Users(user_first_name=firstname, user_last_name=lastname, email=email_address,organization_id=organization.id,
                         organization_name=organization.name,role="operator",access_token=access_token,
                         refresh_token=refresh_token)
            user.save()
            response_data = {
                "access_token":access_token,
                "display_name":display_name,
                "email":email_address,
                "role":"operator"
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

@user_router.get('/validate_token')
async def validate_token(request: Request):
    try:
        headers = request.headers
        email,organization = validate(headers)
        if email:
            user = Users.select().where(Users.email == email).first()
            if user:
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "User Authorized", "data": email})
            else:
                return JSONResponse(status_code=401,
                                    content={"code": 401,
                                             "message": "Invalid Token"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=401,
                                content={"code": 401,
                                         "message": "Invalid Token"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.get('/validate_email')
async def validate_email(request: Request):
    try:
        headers = request.headers
        email,organization = validate(headers)
        if email:
            user = Users.select().where(Users.email == email).first()
            if user:
                if user.email_valid:
                    return JSONResponse(status_code=400,
                                        content={"code": 400, "message": "Email Already Verified", "data": email})
                query = Users.update(email_valid=True).where(Users.email == email)
                query.execute()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "Email Verified", "data": email})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Invalid Token"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=401,
                                content={"code": 401,
                                         "message": "Invalid Token"})
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
            display_name = ""
            if "names" in user_data:
                display_name = user_data.get("names")[0].get("displayName")
            if "emailAddresses" in user_data:
                email_address = user_data.get("emailAddresses")[0].get("value")
            organization = email_address.split('@')[1].split(".")[0]
            user = Users.select().where((Users.email == email_address) & (Users.organization_name == organization)).first()
            if user:
                payload = {
                    "email": email_address,
                    "organization": organization,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=int(os.getenv("TOKEN_EXPIRY")))
                }
                # Define the secret key
                secret_key = os.getenv("SECRET_KEY")

                # Generate the access token
                access_token = jwt.encode(payload, secret_key, algorithm='HS256')
                query = Users.update(access_token=access_token).where(Users.email == email_address)
                updated_rows = query.execute()
                response_data = {
                    "access_token": access_token,
                    "email": email_address,
                    "display_name": display_name,
                    "role":user.role
                }
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OK", "data": response_data})

            return JSONResponse(status_code=401,
                                content={"code": 401,
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
                query = Users.update(password=new_password,otp="").where(Users.email == email)
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
                handler.send_otp_email(email,random_str)
                query = Users.update(otp=random_str, otp_expiry =datetime.datetime.now() + datetime.timedelta(seconds=300)).where(Users.email == email)
                updated_rows = query.execute()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OTP SENT", "data": email})
            else:
                return JSONResponse(status_code=401,
                                    content={"code": 401,
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

@user_router.post('/enable_mfa')
async def enable_mfa(request: Request):
    try:
        headers = request.headers
        data = await request.json()
        mfa_type = data.get("mfa_type")
        email,organization = validate(headers)
        if email and mfa_type in ["email","authenticator"]:
            user = Users.select().where(Users.email == email).first()
            if user:
                query = Users.update(mfa=True,mfa_type=mfa_type).where(Users.email == email)
                updated_rows = query.execute()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "MFA Enabled", "data": ""})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Unauthorized User"})

        else:
            applog.error("Api execution failed with 400 status code ")
            return JSONResponse(status_code=401,
                                content={"code": 401,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.post('/change_password')
async def change_password(request: Request):
    try:
        headers = request.headers
        data = await request.json()
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        email, organization = validate(headers)
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
                return JSONResponse(status_code=401,
                                    content={"code": 401,
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

@user_router.get('/get-profile')
async def get_profile(request: Request):
    try:
        headers = request.headers
        email,organization = validate(headers)
        if email:
            user = Users.select().where(Users.email == email).first()
            if user:
                set_passsword = True
                password = user.password
                if password is None or password=="":
                    set_passsword=False

                response_data = {
                    "email": email,
                    "first_name": user.user_first_name,
                    "last_name": user.user_last_name,
                    "organization": user.organization_name,
                    "mfa_enabled" : user.mfa,
                    "set_password":set_passsword,
                    "mfa_type": user.mfa_type,
                    "mfa_verified": user.mfa_verified,
                    "role": user.role
                }
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "Success", "data": response_data})
            else:
                return JSONResponse(status_code=401,
                                    content={"code": 401,
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

@user_router.post('/verify_otp')
async def verify_otp(request: Request):
    try:
        data = await request.json()
        email = data.get("email")
        otp = data.get("otp")
        if email and otp:
            user = Users.select().where(Users.email == email).first()
            if user:
                if user.otp==otp:
                    if user.otp_expiry > datetime.datetime.now():
                        return JSONResponse(status_code=200,
                                            content={"code": 200, "message": "OTP verified", "data": ""})
                    else:
                        return JSONResponse(status_code=400,
                                            content={"code": 400,
                                                     "message": "OTP Expired"})
                else:
                    return JSONResponse(status_code=400,
                                        content={"code": 400,
                                                 "message": "Invalid OTP"})
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

@user_router.get('/generate_mfa_uri')
async def get_profile(request: Request):
    try:
        headers = request.headers
        email,organization = validate(headers)
        if email:
            user = Users.select().where(Users.email == email).first()
            if user:
                if user.mfa_verified == False:
                    secret_key , uri = generate_mfa_uri(email)
                    query = Users.update(mfa_uri=uri,mfa_secret=secret_key).where(Users.email == email)
                    query.execute()
                    response_data = {
                        "uri":uri
                    }
                    return JSONResponse(status_code=200,
                                        content={"code": 200, "message": "Success", "data": response_data})
                else:
                    uri = user.mfa_uri
                    response_data = {
                        "uri": uri
                    }
                    return JSONResponse(status_code=200,
                                        content={"code": 200, "message": "Success", "data": response_data})

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

@user_router.post('/verify_mfa_otp')
async def verify_mfa_otp(request: Request):
    try:
        data = await request.json()
        headers = request.headers
        email, organization = validate(headers)
        otp = data.get("otp")
        if email and otp:
            user = Users.select().where(Users.email == email).first()
            secret_key = user.mfa_secret
            store_otp = validate_otp(otp, secret_key)
            if user and secret_key and store_otp==otp:
                query = Users.update(mfa_verified=True).where(Users.email == email)
                query.execute()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OTP verified", "data": ""})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "Invalid OTP"})

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

@user_router.post('/edit_user')
async def change_role(request: Request):
    try:
        headers = request.headers
        data = await request.json()
        first_name = data.get("first_name",None)
        last_name = data.get("last_name",None)
        role = data.get("role")
        email_to_change = data.get("email")
        email,organization = validate(headers)
        if email and email_to_change and role in ["admin","operator","researcher","superadmin"]:
            user = Users.select().where(Users.email == email).first()
            if user and user.role in ["admin","superadmin"]:
                user_change = Users.select().where(Users.email == email_to_change).first()
                if user_change:
                    if role!="superadmin":
                        query = Users.update(role=role).where(Users.email == email_to_change)
                        updated_rows = query.execute()
                    if first_name:
                        query = Users.update(user_first_name=first_name).where(Users.email == email_to_change)
                        updated_rows = query.execute()
                    if last_name:
                        query = Users.update(user_last_name=last_name).where(Users.email == email_to_change)
                        updated_rows = query.execute()
                    return JSONResponse(status_code=200,
                                        content={"code": 200, "message": "User Updated", "data": ""})
                else:
                    return JSONResponse(status_code=400,
                                        content={"code": 400,
                                                 "message": "User you want to change doesn't exist"})
            else:
                return JSONResponse(status_code=401,
                                    content={"code": 401,
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

@user_router.post('/add_org')
async def add_org(request: Request):
    try:
        headers = request.headers
        data = await request.json()
        name = data.get("name")
        website = data.get("website")
        details = data.get("details")
        email,organization = validate(headers)
        if email and name and website and details:
            user = Users.select().where(Users.email == email).first()
            if user and user.role == "superadmin":
                organization = Organization.select().where(Organization.name == name).first()
                if organization:
                    return JSONResponse(status_code=400,
                                        content={"code": 400,
                                                 "message": "Already Present"})
                else:
                    org = Organization(name=name, website=website, details=details)
                    org.save()
                    return JSONResponse(status_code=200,
                                        content={"code": 200,
                                                 "message": "Organization added"})
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

@user_router.get('/get_user_management')
async def add_org(request: Request):
    try:
        headers = request.headers
        param = request.query_params
        offset = int(param.get("offset", 0))
        limitt = int(param.get("limit", 20))
        email,organization = validate(headers)
        if email:
            user = Users.select().where(Users.email == email).first()
            if user and user.role == "superadmin":
                users = list(Users.select().offset(offset).limit(limitt))
                user_list = []
                response = {}
                for u in users:
                    resp = {}
                    resp["user_id"] = u.id
                    resp["first_name"] = u.user_first_name
                    resp["last_name"] = u.user_last_name
                    resp["created_at"] = u.created_at.strftime("%m/%d/%Y, %H:%M:%S")
                    resp["role"] = u.role
                    resp["email"] = u.email
                    resp["status"] = "active"
                    user_list.append(resp)
                response["total_count"] = Users.select().count()
                response["user_list"] = user_list
                response["limit"] = limitt
                response["offset"] = offset
                return JSONResponse(status_code=200,
                                    content={"code": 200,
                                             "message": "Success","data": response})
            elif user:
                organization = user.organization_name
                user_list = []
                users = list(Users.select().where(Users.organization_name==organization).offset(offset).limit(limitt))
                response = {}
                for u in users:
                    resp = {}
                    resp["user_id"] = u.id
                    resp["first_name"] = u.user_first_name
                    resp["last_name"] = u.user_last_name
                    resp["created_at"] = u.created_at.strftime("%m/%d/%Y, %H:%M:%S")
                    resp["role"] = u.role
                    resp["email"] = u.email
                    resp["status"] = "active"
                    user_list.append(resp)
                response["total_count"] = Users.select().where(Users.organization_name==organization).count()
                response["user_list"] = user_list
                response["limit"] = limitt
                response["offset"] = offset
                return JSONResponse(status_code=200,
                                    content={"code": 200,
                                             "message": "Success","data": response})
        else:
            return JSONResponse(status_code=401,
                                content={"code": 401,
                                         "message": "Unauthorized User"})


    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@user_router.get('/get_all_org')
async def add_org(request: Request):
    try:
        headers = request.headers
        param = request.query_params
        offset = int(param.get("offset", 0))
        limitt = int(param.get("limit", 20))
        email,organization = validate(headers)
        if email:
            user = Users.select().where(Users.email == email).first()
            if user and user.role == "superadmin":
                organization = list(Organization.select().offset(offset).limit(limitt))
                if organization:
                    response = {}
                    org_list = []
                    for org in organization:
                        resp = {}
                        resp["name"] = org.name
                        resp["id"] = org.id
                        resp["created_at"] = org.created_at.strftime("%m/%d/%Y, %H:%M:%S")
                        resp["website"] = org.website
                        resp["details"] = org.details
                        org_list.append(resp)
                    response["limit"] = limitt
                    response["offset"] = offset
                    response["total_count"] = Organization.select().count()
                    response["org_list"] = org_list
                    return JSONResponse(status_code=200,
                                        content={"code": 200,
                                                 "message": "Success","data":response})
                else:

                    return JSONResponse(status_code=204,
                                        content={"code": 204,
                                                 "message": "Data not found"})
            else:
                return JSONResponse(status_code=401,
                                    content={"code": 401,
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

@user_router.post('/update_user_profile')
async def change_role(request: Request):
    try:
        headers = request.headers
        data = await request.json()
        first_name = data.get("first_name",None)
        last_name = data.get("last_name",None)
        email,organization = validate(headers)
        if email and organization and first_name and last_name:
            user = Users.select().where(Users.email == email).first()
            if user:
                if first_name:
                    query = Users.update(user_first_name=first_name).where(Users.email == email)
                    updated_rows = query.execute()
                if last_name:
                    query = Users.update(user_last_name=last_name).where(Users.email == email)
                    updated_rows = query.execute()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "User Updated", "data": ""})
            else:
                return JSONResponse(status_code=400,
                                    content={"code": 400,
                                             "message": "User you want to change doesn't exist"})
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
