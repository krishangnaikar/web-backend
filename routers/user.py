from __future__ import annotations

import traceback

from fastapi.security import HTTPBearer

auth_scheme = HTTPBearer()
from common.log_data import ApplicationLogger as applog
from common.messages import Messages
from fastapi import APIRouter, Request, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from model.core.models import Users

user_router = APIRouter(
    prefix='/user'
)


@user_router.post('/signup')
async def signup(request: Request):
    """ get ivr mini statement function
        Args: Input Parameter
            Bearer Token
        Returns:
            Response JSON
        """
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
        applog.info(f" IVR MINI STATEMENT | {data.customer_id} | Calling Manager function")
        mini_statement_app_response = ""
        if mini_statement_app_response['code'] == 200:
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "OK", "data": mini_statement_app_response['data']})
        else:
            applog.error(f"| {data} | Api execution failed with 500 status code ")
            return JSONResponse(status_code=mini_statement_app_response['code'],
                                content={"code": mini_statement_app_response['code'],
                                         "message": mini_statement_app_response['message']})
    except Exception as exp:
        applog.error("Exception occured in ivrministatementlist: \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

from __future__ import annotations

import traceback

from fastapi.security import HTTPBearer

auth_scheme = HTTPBearer()
from common.log_data import ApplicationLogger as applog
from common.messages import Messages
from fastapi import APIRouter, Request, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from model.core.models import Users

user_router = APIRouter(
    prefix='/user'
)


@user_router.post('/ssosignup')
async def ssosignup(request: Request):
    """ get ivr mini statement function
        Args: Input Parameter
            Bearer Token
        Returns:
            Response JSON
        """
    try:
        header = request.headers
        data = await request.json()
        auth_code = data.get("authprization_code")
        if auth_code:
            user = Users(user_first_name=first_name, user_last_name=last_name, email=email)
            user.set_password(password)  # Hashes the password and stores it
            user.save()
            # Users.create(**datadict)
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "OK", "data": data})
        applog.info(f" IVR MINI STATEMENT | {data.customer_id} | Calling Manager function")
        mini_statement_app_response = ""
        if mini_statement_app_response['code'] == 200:
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "OK", "data": mini_statement_app_response['data']})
        else:
            applog.error(f"| {data} | Api execution failed with 500 status code ")
            return JSONResponse(status_code=mini_statement_app_response['code'],
                                content={"code": mini_statement_app_response['code'],
                                         "message": mini_statement_app_response['message']})
    except Exception as exp:
        applog.error("Exception occured in ivrministatementlist: \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass


