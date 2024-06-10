import os
import sys
from logging.config import dictConfig
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI

from routers.user import user_router
from routers.agent import agent_router
from routers.dashboard import dashboard_router
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config'))
from config.custom_log  import log_config
from common.app_constants import AppConstants
from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from common.messages import Messages

"""
Imports: The script starts with importing necessary modules and packages like os, sys, uvicorn, load_dotenv,
FastAPI, etc. It also imports routers for different functionalities like user_router, agent_router, 
and dashboard_router.

Logging Configuration: It configures logging using a dictionary configuration provided in log_config.

Environment Variables: It loads environment variables from a .env file.

FastAPI Application Setup:

An instance of the FastAPI application is created.

Exception handlers are defined for handling HTTP exceptions (StarletteHTTPException) and request validation 
errors (RequestValidationError).

CORS middleware is added to allow cross-origin requests.

Routers for different functionalities (user_router, agent_router, dashboard_router) are included in the 
application.

CORS middleware is added to enable Cross-Origin Resource Sharing.

Exception Handlers:
http_exception_handler handles HTTP exceptions and returns JSON responses with appropriate status codes and 
error messages.

validation_exception_handler handles request validation errors, removes duplicate error messages, and 
returns JSON responses with appropriate status codes and error details.

Middleware (Commented): There's a commented section where middleware (JwtMiddleWareToken) is mentioned 
but not included in the application.

Server Execution: If the script is run directly, it starts the UVicorn server with the FastAPI 
application running on host "0.0.0.0" and port 8000.


This script sets up a FastAPI application with exception handling, CORS support, and includes routers for 
different API functionalities. It's configured to run as a server using UVicorn.

"""


dictConfig(log_config)

# env loading
env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(env_file, override=True)

app = FastAPI()

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content=jsonable_encoder(exc.detail),
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    details = exc.errors()  # dublicattion coming
    actual_dict = {
        "code": AppConstants.CODE_INVALID_REQUEST,
        "message": Messages.INVALID_FORMAT,
    }
    new_list = []
    for dictionary in details:
        if dictionary not in new_list:
            new_list.append(dictionary)

    modified_list = []
    for values in new_list:
        new_dict = {
            "field": values['loc'][1],
            "message": "Invalid " + values['loc'][1]
        }
        modified_list.append(new_dict)
        actual_dict['errors'] = modified_list
    return JSONResponse(
        status_code=AppConstants.CODE_INVALID_REQUEST,
        content=jsonable_encoder(actual_dict),
    )



app.include_router(user_router)
app.include_router(agent_router)
app.include_router(dashboard_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# calling middleware
# JwtMiddleWareToken = JwtMiddleWare(logger=logging)
# app.add_middleware(BaseHTTPMiddleware, dispatch=JwtMiddleWareToken)
if __name__ == "__main__":
    uvicorn.run('main:app', host="0.0.0.0" ,port=8000)
