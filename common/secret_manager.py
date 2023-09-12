# import json
# import os
#
# import boto3
# from aws_secretsmanager_caching import SecretCache, SecretCacheConfig
# from common.parameter_store import get_parameter_values
# from functools import lru_cache
#
# def SecretKeys():
#     """
#     This function make connection with aws secret manager and create a SecretCacheConfig object
#     :return:
#         SecretCache object
#     """
#     try:
#         session = boto3.session.Session()
#         if os.getenv("environment") == "local":
#             client = session.client(os.getenv("aws_secrete_manager_service"),
#                                     region_name=os.getenv("aws_secrete_manager_region"),
#                                     aws_access_key_id=os.getenv("aws_access_key"),
#                                     aws_secret_access_key=os.getenv("aws_secret_access_key"))
#
#         else:
#             client = session.client(os.getenv("aws_secrete_manager_service"),
#                                     region_name=os.getenv("aws_secrete_manager_region"))
#
#         cache_config = SecretCacheConfig(secret_refresh_interval=int(os.getenv("secret_refresh_interval")))
#
#         cache = SecretCache(config=cache_config, client=client)
#
#         return cache
#
#     except Exception:
#         raise
#
#
# @lru_cache()
# def get_secret_cache():
#     """
#     This function will cache the secret manager cache object to fastAPI cache
#     """
#
#     return SecretKeys()
#
#
# def get_secret_values():
#     """
#     This function take secretCache object from routers config, if it's not there then call SecretKeys function and get the
#     object,
#     Using that object it will call aws secret manager and get the all keys and values in dictionary form.
#     :return:
#         Dictionary of secret keys and values
#     """
#     try:
#         cache = get_secret_cache()
#         Secret = cache.get_secret_string(os.getenv("aws_secrete_manager_service_id"))
#
#         return json.loads(Secret)
#     except Exception:
#         raise
#
# @lru_cache()
# def get_param_value():
#     return get_parameter_values()
#
# class SecreteData:
#     """
#     This class assign all the secrete values and parameter store values to the variables
#     """
#
#     def __init__(self):
#         SECRET = get_secret_values()
#         PARAMETER = get_param_value()
#         self.PORT = PARAMETER["APPLICATION_PORT"]
#         self.DB_USER = SECRET["DB_USER"]
#         self.DB_PASS = SECRET["DB_PASS"]
#         self.DB_HOST = SECRET["DB_HOST"]
#         self.DB_DRIVER = PARAMETER["DB_DRIVER"]
#         self.BASE_URL = SECRET["BASE_URL"]
#         self.IVR_DB_NAME = SECRET["IVR_DB_NAME"]
#         self.IVR_SCHEMA = PARAMETER["IVR_SCHEMA"]
#         self.POOL_SIZE = PARAMETER["POOL_SIZE"]
#         self.IDENTITY_JWT_TOKEN = SECRET['IDENTITY_JWT_TOKEN']
#         self.IDENTITY_JWT_SECRET = SECRET['IDENTITY_JWT_SECRET']
#         self.CREDIT_CARD_JWT_TOKEN = SECRET['CREDIT_CARD_JWT_TOKEN']
#         self.CREDIT_CARD_JWT_SECRET = SECRET['CREDIT_CARD_JWT_SECRET']
#         self.FRESHWORKS_AUTH_TOKEN = SECRET['FRESHWORKS_AUTH_TOKEN']
#         self.FRESHWORKS_BASE_URL = SECRET['FRESHWORKS_BASE_URL']
#         self.IVR_APP_BASE_URL = SECRET['IVR_APP_BASE_URL']
#         self.FRESHWORKS_IVR_JWT_SECRET = SECRET['FRESHWORKS_IVR_JWT_SECRET']
#         self.FRESHWORKS_EXTERNAL_JWT_SECRET = SECRET['FRESHWORKS_EXTERNAL_JWT_SECRET']
#         self.FRESHWORKS_EXTERNAL_JWT_TOKEN = SECRET['FRESHWORKS_EXTERNAL_JWT_TOKEN']
#         self.FRESHWORKS_IVR_JWT_TOKEN = SECRET['FRESHWORKS_IVR_JWT_TOKEN']
#         self.INTERNAL_BASE_URL = SECRET["INTERNAL_BASE_URL"]
