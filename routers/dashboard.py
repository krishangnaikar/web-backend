from __future__ import annotations
import json
import math
import os
import random
import traceback
import jwt
import pytz

from model.agent.models import Agent,AgentMetrics,File,UserFilePermission
from fastapi.security import HTTPBearer
from peewee import fn , JOIN
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

dashboard_router = APIRouter(
    prefix='/dashboard'
)
@dashboard_router.get("/user_management")
def get_user_management(request:Request):
    try:
        headers = request.headers
        email, organization = validate(headers)
        if email and organization:
            user = Users.select().where(Users.email == email).first()
            if user.role == "superadmin":
                admin_count = Users.select().where(Users.role == "admin").count()
                operator_count = Users.select().where(Users.role == "operator").count()
                researcher_count = Users.select().where(Users.role == "researcher").count()
                response = {"admin_count":admin_count,"researcher_count":researcher_count,"operator_count":operator_count}
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "", "data": response})
            else:
                org = user.organization_name
                admin_count = Users.select().where((Users.role == "admin") & (Users.organization_name == org)).count()
                operator_count = Users.select().where((Users.role == "operator") & (Users.organization_name == org)).count()
                researcher_count = Users.select().where((Users.role == "researcher") & (Users.organization_name == org)).count()
                response = {"admin_count": admin_count, "researcher_count": researcher_count,
                            "operator_count": operator_count}
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "", "data": response})
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
@dashboard_router.get("/file_type_count")
def get_file_type(request:Request):
    try:
        headers = request.headers
        email, organization = validate(headers)
        if email and organization:
            response={}
            user = Users.select().where(Users.email == email).first()
            if user.role=="superadmin":
                response["without_encryption_count"] = File.select().where(
                    File.encryption_status == "Not Encrypted").count()
                query = (
                    File
                    .select()
                    .join(UserFilePermission, JOIN.LEFT_OUTER, on=(File.id == UserFilePermission.file_id))
                    .where(UserFilePermission.file_id >> None)
                # Filter where FilePermission.file_id is NULL
                )

                # Count the number of files without permissions
                count = query.count()
                response["without_access_control_count"] = count
                query = (
                    File
                    .select()
                    .join(UserFilePermission, JOIN.LEFT_OUTER, on=(File.id == UserFilePermission.file_id))
                    .where((UserFilePermission.file_id >> None) & (File.encryption_status == "Not Encrypted"))
                    # Filter where FilePermission.file_id is NULL
                )
                count = query.count()
                response["without_access_control_and_encryption_count"] = count
                query = File.select(File.file_type, fn.COUNT(File.id).alias('file_count')).group_by(File.file_type)
                result = query.dicts()
                response["Genomic"] = 0
                response["PHI"] = 0
                response["PII"] = 0
                response["PCI"] = 0
                response["Unknown"] = 0
                for row in result:
                    if row["file_type"] in ["FASTAQ", "fasta", "fastaq", "FASTA", "BAM"]:
                        response["Genomic"] += row["file_count"]
                    elif row["file_type"] in ["PHI", "PII", "PCI"]:
                        response[row["file_type"]] = row["file_count"]
                    else:
                        response["Unknown"]+= row["file_count"]
            else:
                org = user.organization_id
                response["without_encryption_count"] = File.select().where((File.encryption_status=="Not Encrypted") & (File.organization_id==str(org))).count()
                query = (
                    File
                    .select()
                    .join(UserFilePermission, JOIN.LEFT_OUTER, on=(File.id == UserFilePermission.file_id))
                    .where((UserFilePermission.file_id >> None) & (UserFilePermission.organization_id == str(org)) )  # Filter where FilePermission.file_id is NULL
                )

                # Count the number of files without permissions
                count = query.count()
                response["without_access_control_count"] =count
                query = (
                    File
                    .select()
                    .join(UserFilePermission, JOIN.LEFT_OUTER, on=(File.id == UserFilePermission.file_id))
                    .where((UserFilePermission.file_id >> None) & (UserFilePermission.organization_id == str(org)) & (File.encryption_status == "Not Encrypted"))
                    # Filter where FilePermission.file_id is NULL
                )
                count = query.count()
                response["without_access_control_and_encryption_count"] = count
                query = File.select(File.file_type, fn.COUNT(File.id).alias('file_count')).where(File.organization_id == str(org) ).group_by(File.file_type)
                result = query.dicts()
                response["Genomic"] = 0
                response["PHI"] = 0
                response["PII"] = 0
                response["PCI"] = 0
                response["Unknown"]=0
                for row in result:
                    if row["file_type"] in ["FASTAQ","fasta","fastaq","FASTA","BAM"]:
                        response["Genomic"] += row["file_count"]
                    elif row["file_type"] in ["PHI","PII","PCI"]:
                        response[row["file_type"]] = row["file_count"]
                    else:
                        response["Unknown"]+= row["file_count"]
            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "", "data": response})

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

@dashboard_router.get("/agent_status_count")
def get_agent_status(request:Request):
    try:
        headers = request.headers
        email, organization = validate(headers)
        if email and organization:
            response={}
            user = Users.select().where(Users.email == email).first()
            if user.role == "superadmin":
                five_minutes_ago = (datetime.datetime.now(pytz.utc) - datetime.timedelta(minutes=5)).replace(tzinfo=None)
                # Query to find the count of rows
                query = (
                    AgentMetrics
                    .select()
                    .where(
                        (AgentMetrics.updated_at > five_minutes_ago) &
                        (AgentMetrics.metric_name == 'CPU Usage') &
                        (AgentMetrics.metric_value > 90.0)
                    )
                )
                # Execute the query and get the result
                response["unhealthy_status"] = query.count()
                query = (
                    AgentMetrics
                    .select(fn.COUNT(AgentMetrics.id).alias('count'))
                    .where(
                        (AgentMetrics.updated_at >= five_minutes_ago) &
                        (AgentMetrics.metric_name == 'CPU Usage') &
                        (AgentMetrics.metric_value < 80.0)
                    )
                )
                # Execute the query and get the result
                response["healthy_status"] = query.scalar()
                query = (
                    AgentMetrics
                    .select(fn.COUNT(AgentMetrics.id).alias('count'))
                    .where(
                        (AgentMetrics.updated_at >= five_minutes_ago) &
                        (AgentMetrics.metric_name == 'CPU Usage') &
                        (AgentMetrics.metric_value >= 80.0) &
                        (AgentMetrics.metric_value <= 90.0)
                    )
                )
                # Execute the query and get the result
                response["critical_status"] = query.scalar()
                response["online_agents"] = response["critical_status"] + response["healthy_status"] + response["unhealthy_status"]
                offine_count = AgentMetrics.select(fn.COUNT(fn.DISTINCT(AgentMetrics.agent_id))).scalar() - response["critical_status"] - response["healthy_status"] - response["unhealthy_status"]
                # Execute the query and get the result
                response["offile_agents"] = offine_count
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "", "data": response})
            else:
                five_minutes_ago = (datetime.datetime.now(pytz.utc) - datetime.timedelta(minutes=5)).replace(tzinfo=None)
                org = user.organization_id
                # Query to find the count of rows
                query = (
                    AgentMetrics
                    .select()
                    .where(
                        (AgentMetrics.updated_at > five_minutes_ago) &
                        (AgentMetrics.metric_name == 'CPU Usage') &
                        (AgentMetrics.metric_value > 90.0) &
                        (AgentMetrics.organization_id == str(org))
                    )
                )
                # Execute the query and get the result
                response["unhealthy_status"] = query.count()
                query = (
                    AgentMetrics
                    .select(fn.COUNT(AgentMetrics.id).alias('count'))
                    .where(
                        (AgentMetrics.updated_at >= five_minutes_ago) &
                        (AgentMetrics.metric_name == 'CPU Usage') &
                        (AgentMetrics.metric_value < 80.0) &
                        (AgentMetrics.organization_id == str(org))
                    )
                )
                # Execute the query and get the result
                response["healthy_status"] = query.scalar()
                query = (
                    AgentMetrics
                    .select(fn.COUNT(AgentMetrics.id).alias('count'))
                    .where(
                        (AgentMetrics.updated_at >= five_minutes_ago) &
                        (AgentMetrics.metric_name == 'CPU Usage') &
                        (AgentMetrics.metric_value >= 80.0) &
                        (AgentMetrics.metric_value <= 90.0) &
                        (AgentMetrics.organization_id == str(org))
                    )
                )
                # Execute the query and get the result
                response["critical_status"] = query.scalar()
                response["online_agents"] = response["critical_status"] + response["healthy_status"] + response[
                    "unhealthy_status"]
                offine_count = AgentMetrics.select(fn.COUNT(fn.DISTINCT(AgentMetrics.agent_id))).where(AgentMetrics.organization_id == str(org)).scalar() - response[
                    "critical_status"] - response["healthy_status"] - response["unhealthy_status"]
                # Execute the query and get the result
                response["offile_agents"] = offine_count
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "", "data": response})

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

@dashboard_router.get("/get_control_access")
def get_control_access(request:Request):
    try:
        headers = request.headers
        email, organization = validate(headers)
        if email and organization:
            response={}
            user = Users.select().where(Users.email == email).first()
            if user.role=="superadmin":
                response["security_control_missing"] = File.select().where(
                    File.encryption_status == "Not Encrypted").count()
                response["security_control_in_place"] = File.select().where(
                    File.encryption_status == "Encrypted").count()

            else:
                org = user.organization_id
                response["security_control_missing"] = File.select().where((File.encryption_status=="Not Encrypted") & (File.organization_id==str(org))).count()
                response["security_control_in_place"] = File.select().where((File.encryption_status=="Encrypted") & (File.organization_id==str(org))).count()

            return JSONResponse(status_code=200,
                                content={"code": 200, "message": "", "data": response})

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