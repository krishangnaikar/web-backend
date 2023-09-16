import os
import sys
from logging.config import dictConfig

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI

from routers.user import user_router
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config'))
from config.custom_log  import log_config
from common.app_constants import AppConstants
from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from common.messages import Messages


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

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
# calling middleware
# JwtMiddleWareToken = JwtMiddleWare(logger=logging)
# app.add_middleware(BaseHTTPMiddleware, dispatch=JwtMiddleWareToken)
if __name__ == "__main__":
    uvicorn.run('main:app', host="127.0.0.1", port=8000)
