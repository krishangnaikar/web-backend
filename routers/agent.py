from __future__ import annotations
import json
import math
import os
import pytz
import random
import traceback
import jwt
from fastapi.security import HTTPBearer
from common.services.email_service import EmailHandler
auth_scheme = HTTPBearer()
from common.log_data import ApplicationLogger as applog
from common.messages import Messages
from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from common.services.jwt_decoder import validate
from fastapi.responses import JSONResponse
from model.core.models import Users
from model.agent.models import Agent,AgentMetrics,File,UserFilePermission,AgentFileAudit
import requests
import datetime

agent_router = APIRouter(
    prefix='/agent'
)

@agent_router.get('/agent_status_list')
async def login(request: Request):
    try:
        headers = request.headers
        param = request.query_params
        offset = int(param.get("offset",0))
        limitt = int(param.get("limit",20))
        email, organization = validate(headers)
        if organization and email:
            user = Users.select().where(Users.email == email).first()
            if user:
                if user.role=="operator" or user.role=="admin":
                    organization = user.organization_id
                    response = {}
                    agents = []
                    cpu_query = list(
                        AgentMetrics
                        .select(AgentMetrics,Agent)  # Include Agent location)
                        .join(Agent, on=(AgentMetrics.agent_id == Agent.id))  # Join with Agent table
                        .where((AgentMetrics.organization_id == str(organization)) & (
                                    AgentMetrics.metric_name == "CPU Usage"))
                        .order_by(AgentMetrics.agent_id, AgentMetrics.updated_at.desc())
                        .distinct(AgentMetrics.agent_id)
                        .offset(offset)
                        .limit(limitt)
                    )
                    ram_query = list(
                        AgentMetrics
                        .select()
                        .where((AgentMetrics.organization_id == str(organization)) & (AgentMetrics.metric_name == "ram_usage"))
                        .order_by(AgentMetrics.agent_id, AgentMetrics.updated_at.desc())
                        .distinct(AgentMetrics.agent_id)
                        .offset(offset)
                        .limit(limitt)      # Ensures only the latest rows per agent are returned
                    )
                    disk_query = list(
                        AgentMetrics
                        .select()
                        .where((AgentMetrics.organization_id == str(organization)) & (
                                    AgentMetrics.metric_name == "disk_usage"))
                        .order_by(AgentMetrics.agent_id, AgentMetrics.updated_at.desc())
                        .distinct(AgentMetrics.agent_id)
                        .offset(offset)
                        .limit(limitt)  # Ensures only the latest rows per agent are returned
                    )
                    agent_count = Agent.select().where(Agent.organization_id == str(organization)).count()
                    response["total_count"] = agent_count
                    response["offset"] = offset
                    response["limit"] = limitt
                    if len(cpu_query)>0:
                        date = cpu_query[0].updated_at
                    for i in range(len(cpu_query)):
                        d = {}
                        d["id"]= agent_id = cpu_query[i].agent_id
                        d["location"] = cpu_query[i].agent.ip_address
                        d["name"] = cpu_query[i].agent.running_as_user_name
                        d["last_update_time"] =cpu_query[i].updated_at.strftime("%m/%d/%Y, %H:%M:%S")
                        d["cpu_percentage"] = cpu_query[i].metric_value
                        d["ram_percentage"] = ram_query[i].metric_value
                        d["disk_percentage"] = disk_query[i].metric_value
                        if (datetime.datetime.now(pytz.utc)  - cpu_query[i].updated_at).total_seconds() > 300:
                            d["cpu_usage"] = "offline"
                            d["ram_usage"] = "offline"
                            d["disk_usage"] = "offline"
                            d["alive_status"] = "off"
                        else:
                            d["cpu_usage"] = "healthy" if cpu_query[i].metric_value <= 80 else ("critical" if cpu_query[i].metric_value>=90  else "unhealthy")
                            d["ram_usage"] = "healthy" if ram_query[i].metric_value <= 80 else ("critical" if ram_query[i].metric_value>=90  else "unhealthy")
                            d["disk_usage"] = "healthy" if disk_query[i].metric_value <= 80 else ("critical" if disk_query[i].metric_value>=90  else "unhealthy")
                            d["alive_status"] = "on"
                        agents.append(d)
                    response["list"] = agents

                    # Users.create(**datadict)
                    return JSONResponse(status_code=200,
                                        content={"code": 200, "message": "OK", "data": response})
                if user.role=="superadmin":
                    organization = user.organization_id
                    response = {}
                    agents = []
                    cpu_query = list(
                        AgentMetrics
                        .select(AgentMetrics, Agent)
                        .join(Agent, on=(AgentMetrics.agent_id == Agent.id))  # Join with Agent table
                        .where(AgentMetrics.metric_name=="CPU Usage")
                        .order_by(AgentMetrics.agent_id, AgentMetrics.updated_at.desc())
                        .distinct(AgentMetrics.agent_id)
                        .offset(offset)
                        .limit(limitt)       # Ensures only the latest rows per agent are returned
                    )
                    ram_query = list(
                        AgentMetrics
                        .select()
                        .where(AgentMetrics.metric_name == "ram_usage")
                        .order_by(AgentMetrics.agent_id, AgentMetrics.updated_at.desc())
                        .distinct(AgentMetrics.agent_id)
                        .offset(offset)
                        .limit(limitt)      # Ensures only the latest rows per agent are returned
                    )
                    disk_query = list(
                        AgentMetrics
                        .select()
                        .where(AgentMetrics.metric_name == "disk_usage")
                        .order_by(AgentMetrics.agent_id, AgentMetrics.updated_at.desc())
                        .distinct(AgentMetrics.agent_id)
                        .offset(offset)
                        .limit(limitt)  # Ensures only the latest rows per agent are returned
                    )
                    agent_count = Agent.select().count()
                    response["total_count"] = agent_count
                    response["offset"] = offset
                    response["limit"] = limitt
                    date = cpu_query[0].updated_at
                    for i in range(len(cpu_query)):
                        d = {}
                        d["id"]= agent_id = cpu_query[i].agent_id
                        d["location"] = cpu_query[i].agent.ip_address
                        d["name"] =cpu_query[i].agent.running_as_user_name
                        d["last_update_time"] =cpu_query[i].updated_at.strftime("%m/%d/%Y, %H:%M:%S")
                        d["cpu_percentage"] = cpu_query[i].metric_value
                        d["ram_percentage"] = ram_query[i].metric_value
                        d["disk_percentage"] = disk_query[i].metric_value
                        if (datetime.datetime.now(pytz.utc)  - cpu_query[i].updated_at).total_seconds() > 300:
                            d["cpu_usage"] = "offline"
                            d["ram_usage"] = "offline"
                            d["disk_usage"] = "offline"
                            d["alive_status"] = "off"
                        else:
                            d["cpu_usage"] = "healthy" if cpu_query[i].metric_value <= 80 else (
                                "critical" if cpu_query[i].metric_value >= 90 else "unhealthy")
                            d["ram_usage"] = "healthy" if ram_query[i].metric_value <= 80 else (
                                "critical" if ram_query[i].metric_value >= 90 else "unhealthy")
                            d["disk_usage"] = "healthy" if disk_query[i].metric_value <= 80 else (
                                "critical" if disk_query[i].metric_value >= 90 else "unhealthy")
                            d["alive_status"] = "on"

                        agents.append(d)
                    response["list"] = agents

                    # Users.create(**datadict)
                    return JSONResponse(status_code=200,
                                        content={"code": 200, "message": "OK", "data": response})
            return JSONResponse(status_code=401,
                                content={"code": 401,
                                         "message": "Unauthorized user"})
        else:
            applog.error(f"|  Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})
    except Exception as exp:
        applog.error("Exception occured : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@agent_router.get('/file_list')
async def login(request: Request):
    try:
        headers = request.headers
        param = request.query_params
        offset = int(param.get("offset",0))
        limitt = int(param.get("limit",20))
        email, organization = validate(headers)
        if organization and email:
            user = Users.select().where(Users.email == email).first()
            if user and user.role=="superadmin":
                response = {}
                file_data = []
                files = list(File
                             .select()
                             .order_by(File.updated_at.desc())
                             .offset(offset)
                             .limit(limitt))
                # Ensures only the latest rows per agent are returned)
                for file in files:
                    data = {}
                    id = file.id
                    data["filename"] = file.file_path.split("/")[-1]
                    if file.file_type in ["FASTA","FASTAQ","BAM"]:
                        data["sensitivity_type"] = "PHI- Genomic"
                    else:
                        data["sensitivity_type"] = file.file_type
                    data["access"] = [[x.user, x.permissions] for x in list(
                        UserFilePermission.select().where(UserFilePermission.file_id == id).limit(3))]
                    data["user_count"] = UserFilePermission.select().where(UserFilePermission.file_id == id).count()
                    data["encryption_status"] = file.encryption_status
                    if data["encryption_status"] == "Not Encrypted" or data["encryption_status"] == "Not encryted":
                        data["encryption_status"] = "plaintext"
                    data["location"] = file.file_path
                    data["location"] = file.storage_type+ " - " + data["location"]
                    data["compression_status"] = file.compression_type
                    if data["encryption_status"] == "Encrypted":
                        data["security_status"] = "Secure"
                    else:
                        data["security_status"] = "Not Secure"
                    if data["encryption_status"] != "Encrypted":
                        data["control_status"] = "Enable Encryption"
                    else:
                        data["control_status"] = "No Change"
                    file_data.append(data)
                response["total_count"] = File.select().count()
                response["offset"] = offset
                response["limit"] = limitt
                response["list"] = file_data
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OK", "data": response})
            elif user:
                organization = user.organization_id
                response = {}
                file_data = []
                files = list(File
                             .select()
                             .where(File.organization_id == str(organization))
                             .order_by(File.updated_at.desc())
                             .offset(offset)
                             .limit(limitt))
                # Ensures only the latest rows per agent are returned)
                for file in files:
                    data = {}
                    id = file.id
                    data["filename"] = file.file_path.split("/")[-1]
                    if file.file_type in ["FASTA", "FASTAQ", "BAM"]:
                        data["sensitivity_type"] = "PHI- Genomic"
                    else:
                        data["sensitivity_type"] = file.file_type
                    data["access"] = [[x.user,x.permissions] for x in list(UserFilePermission.select().where(UserFilePermission.file_id==id).limit(3))]
                    data["user_count"] = UserFilePermission.select().where(UserFilePermission.file_id == id).count()
                    data["encryption_status"] = file.encryption_status
                    if data["encryption_status"] == "Not Encrypted" or data["encryption_status"] == "Not encryted":
                        data["encryption_status"] = "plaintext"
                    data["location"] = file.file_path
                    data["location"] = file.storage_type + " - " + data["location"]
                    data["compression_status"] = file.compression_type
                    if data["encryption_status"] == "Encrypted":
                        data["security_status"] = "Secure"
                    else:
                        data["security_status"] = "Not Secure"
                    if data["encryption_status"]!="Encrypted":
                        data["control_status"] = "Enable Encryption"
                    else:
                        data["control_status"] = "No Change"
                    file_data.append(data)
                response["total_count"] = File.select().where(File.organization_id == str(organization)).count()
                response["offset"] = offset
                response["limit"] = limitt
                response["list"] = file_data
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OK", "data": response})

            return JSONResponse(status_code=401,
                                content={"code": 401,
                                         "message": "Unauthorized user"})
        else:
            applog.error(f"|  Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})

    except Exception as exp:
        applog.error("Exception occured : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@agent_router.post('/file_user_list')
async def login(request: Request):
    try:
        headers = request.headers
        data = await request.json()
        path = data.get("path")
        email, organization = validate(headers)
        if organization and email and path:
            user = Users.select().where(Users.email == email).first()
            if user:
                organization = user.organization_id
                response = {}
                file = File.select().where(File.file_path == path).first()
                id = file.id
                response["users_list"] = [[x.user,x.permissions] for x in list(UserFilePermission.select().where(UserFilePermission.file_id==id))]
                response["user_count"] = UserFilePermission.select().where(UserFilePermission.file_id == id).count()
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OK", "data": response})

            return JSONResponse(status_code=401,
                                content={"code": 401,
                                         "message": "Unauthorized user"})
        else:
            applog.error(f"|  Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})

    except Exception as exp:
        applog.error("Exception occured : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass

@agent_router.get('/audit_logs_list')
async def audit_logs_list(request: Request):
    try:
        headers = request.headers
        param = request.query_params
        offset = int(param.get("offset", 0))
        limitt = int(param.get("limit", 10))
        email, organization = validate(headers)
        if organization and email:
            user = Users.select().where(Users.email == email).first()
            if user.role=="superadmin":
                response = {}
                audits = list(AgentFileAudit
                              .select()
                              .order_by(AgentFileAudit.updated_at.desc())
                              .offset(offset)
                              .limit(limitt))
                audit_list = []
                for audit in audits:
                    res = {}
                    res["User"] = audit.user_name
                    userr = Users.select().where(Users.user_first_name == audit.user_name).first()
                    if userr:
                        res["Role"] = userr.role
                    else:
                        res["Role"] = "non-Truenil user"
                    file_name,time = audit.file_name.split("&@#")[0],   audit.file_name.split("&@#")[1]
                    res["Action"] = audit.operation + " - "+ file_name
                    if time:
                        res["Timestamp"] = time
                    else:
                        res["Timestamp"] = audit.updated_at.strftime("%m/%d/%Y, %H:%M:%S")
                    audit_list.append(res)
                response["limit"] = limitt
                response["offset"] = offset
                response["total_count"] = AgentFileAudit.select().count()
                response["audit_list"] = audit_list
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OK", "data": response})
            else:
                response = {}
                organization = user.organization_id
                orgname = user.organization_name
                audits = list(AgentFileAudit
                             .select()
                             .where(File.organization_id == str(organization))
                             .order_by(AgentFileAudit.updated_at.desc())
                             .offset(offset)
                             .limit(limitt))
                audit_list = []
                for audit in audits:
                    res = {}
                    res["User"] = audit.user_name
                    userr = Users.select().where((Users.user_first_name == audit.user_name) & (Users.organization_name == orgname)).first()
                    if userr:
                        res["Role"] =userr.role
                    else:
                        res["Role"] = "non-Truenil user"
                    file_name, time = audit.file_name.split("&@#")[0], audit.file_name.split("&@#")[1]
                    res["Action"] = audit.operation + " - " + file_name
                    if time:
                        res["Timestamp"] = time
                    else:
                        res["Timestamp"] = audit.updated_at.strftime("%m/%d/%Y, %H:%M:%S")
                    audit_list.append(res)
                response["limit"] = limitt
                response["offset"] = offset
                response["total_count"] = AgentFileAudit.select().where(AgentFileAudit.organization_id == str(organization)).count()
                response["audit_list"] = audit_list
                return JSONResponse(status_code=200,
                                    content={"code": 200, "message": "OK", "data": response})
        else:
            applog.error(f"|  Api execution failed with 400 status code ")
            return JSONResponse(status_code=400,
                                content={"code": 400,
                                         "message": "Invalid Payload"})

    except Exception as exp:
        applog.error("Exception occured : \n{0}".format(traceback.format_exc()))
        raise HTTPException(status_code=500, detail={"code": 500, "message": Messages.SOMETHING_WENT_WRONG})
    finally:
        pass