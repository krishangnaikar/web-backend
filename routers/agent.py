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
from model.agent.models import Agent,AgentMetrics
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
                    date = cpu_query[0].updated_at
                    for i in range(len(cpu_query)):
                        d = {}
                        d["id"]= agent_id = cpu_query[i].agent_id
                        d["location"] = cpu_query[i].agent.ip_address
                        d["name"] = cpu_query[i].agent.running_as_user_name
                        d["last_update_time"] =cpu_query[i].updated_at.strftime("%m/%d/%Y, %H:%M:%S")
                        if (datetime.datetime.now(pytz.utc)  - cpu_query[i].updated_at).total_seconds() > 300:
                            d["cpu_usage"] = "offline"
                            d["ram_usage"] = "offline"
                            d["disk_usage"] = "offline"
                        else:
                            d["cpu_usage"] = "healthy" if cpu_query[i].metric_value <= 80 else ("critical" if cpu_query[i].metric_value>=90  else "unhealthy")
                            d["ram_usage"] = "healthy" if ram_query[i].metric_value <= 80 else ("critical" if cpu_query[i].metric_value>=90  else "unhealthy")
                            d["disk_usage"] = "healthy" if disk_query[i].metric_value <= 80 else ("critical" if cpu_query[i].metric_value>=90  else "unhealthy")
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
                        if (datetime.datetime.now(pytz.utc)  - cpu_query[i].updated_at).total_seconds() > 300:
                            d["cpu_usage"] = "offline"
                            d["ram_usage"] = "offline"
                            d["disk_usage"] = "offline"
                        else:

                            d["cpu_usage"] = "healthy" if cpu_query[i].metric_value <= 80 else (
                                "critical" if cpu_query[i].metric_value >= 90 else "unhealthy")
                            d["ram_usage"] = "healthy" if ram_query[i].metric_value <= 80 else (
                                "critical" if cpu_query[i].metric_value >= 90 else "unhealthy")
                            d["disk_usage"] = "healthy" if disk_query[i].metric_value <= 80 else (
                                "critical" if cpu_query[i].metric_value >= 90 else "unhealthy")
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
