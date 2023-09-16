from playhouse.migrate  import *
from playhouse.reflection import print_table_sql
import datetime
from peewee import *
from playhouse.migrate import Database
from dotenv import load_dotenv
from os import environ
from playhouse.postgres_ext import *
from model.agent.models import Agent, Bucket, File, AgentFile, AgentBucket
from model.core.models import Organization, User , Users
load_dotenv()
PG_HOST = environ.get("POSTGRES_HOST_NAME", default="127.0.0.1")
POSTGRES_USER_NAME = environ.get("POSTGRES_USER_NAME", default="postgres")
POSTGRES_USER_PASSWORD = environ.get("POSTGRES_USER_PASSWORD", default="password")
#initialize connection to database
database = PostgresqlExtDatabase("truenil", user=POSTGRES_USER_NAME,password=POSTGRES_USER_PASSWORD,host=PG_HOST)

migrator = Database(database)

# migrator.create_tables(Organization)
# migrator.create_tables(User)
# migrator.create_tables(Agent)
# migrator.create_tables(Bucket)
# migrator.create_tables(File)
# migrator.create_tables(AgentFile)
print_table_sql(Users)
print(";")
print_table_sql(Organization)
print(";")
print_table_sql(User)
print(";")
print_table_sql(Agent)
print(";")
print_table_sql(Bucket)
print(";")
print_table_sql(File)
print(";")
print_table_sql(AgentFile)
print(";")
print_table_sql(AgentBucket)
print(";")
