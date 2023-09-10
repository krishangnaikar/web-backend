import requests
from common.app_response import AppResponse
# from common.secret_manager import SecreteData
from fastapi.exceptions import HTTPException


# def headers_validation(headers_data):
#     app_response = AppResponse()
#     keys = SecreteData()
#     try:
#         header = {
#             "deviceType": headers_data.get("deviceType"),
#             "appVersion": headers_data.get("appVersion"),
#             "Content-Type": headers_data.get("Content-Type"),
#             "deviceId": headers_data.get("deviceId"),
#             "device": headers_data.get("device"),
#             "Authorization": headers_data.get("Authorization"),
#         }
#         token = headers_data["Authorization"]
#         url = keys.BASE_URL + "/identity/check-token"  # onv
#
#         access_token = token.split()
#         if "Bearer" in access_token:
#             data = access_token[1]
#         else:
#             data = access_token
#         payload = {'accessToken': data}
#
#         response = requests.post(url, headers=header, json=payload)
#         app_response = response.json()
#     except Exception as exp:
#         raise HTTPException(status_code=500, detail="some went wrong {}".format(exp))
#     finally:
#         return app_response


def delete_422_response(data):
    for method in data:
        try:
            if data[method].get("post"):
                del data[method]["post"]["responses"]["422"]
            elif data[method].get("get"):
                del data[method]["get"]["responses"]["422"]
        except KeyError:
            pass
    return data