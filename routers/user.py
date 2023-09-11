from __future__ import annotations

import json
import traceback

from fastapi.security import HTTPBearer

auth_scheme = HTTPBearer()
from common.log_data import ApplicationLogger as applog
from common.messages import Messages
from fastapi import APIRouter, Request, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from model.core.models import Users
import requests
user_router = APIRouter(
    prefix='/user'
)


@user_router.post('/signup')
async def signup(request: Request):
    try:
        header = request.headers
        data = await request.json()
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        email = data.get("email")
        password = data.get("password")
        if first_name and last_name and password and email:
            user = Users(user_first_name=first_name, user_last_name=last_name, email=email)
            user.set_password(password)  # Hashes the password and stores it
            user.save()
            # Users.create(**datadict)
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "OK", "data": data})
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
            REDIRECT_URI = 'http://localhost:8000/user/oauth'
            CLIENT_ID = "319958640423-lgkdd37i6d0eu4v983kvrnve8v6tugjl.apps.googleusercontent.com"
            CLIENT_SECRET = "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"
            token_params = {
                'code':auth_code,
                'client_id': CLIENT_ID,
                'client_secret' : CLIENT_SECRET,
                'redirect_uri' : REDIRECT_URI,
                'grant_type' : 'authorization_code'
            }
            token_url = 'https://oauth2.googleapis.com/token'
            token_response = requests.post(token_url,data=token_params)
            token_data = json.loads(token_response.text)
            access_token = None
            refresh_token = None
            if "access_token" in token_data:
                access_token = token_data.get("access_token")
            if "refresh_token" in token_data:
                refresh_token = token_data.get("refresh_token")
            people_api_url = 'https://people.googleapis.com/v1/people/me'
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
            print(user_data)
            # Users.create(**datadict)
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "OK", "data": user_data})
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
            applog.error(f"| {data} | Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured in : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass


