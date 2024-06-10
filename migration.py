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

"""
Imports: The script imports various modules and classes necessary for database migration, including 
playhouse.migrate, playhouse.reflection, peewee, playhouse.postgres_ext, dotenv, and model classes 
(Agent, Bucket, File, AgentFile, AgentBucket) from their respective modules.

Environment Variables: It loads environment variables from a .env file using load_dotenv(). The 
environment variables include PostgreSQL connection details such as POSTGRES_HOST_NAME, POSTGRES_USER_NAME, 
and POSTGRES_USER_PASSWORD.

Database Connection: It establishes a connection to the PostgreSQL database named "truenil" using the 
provided connection details.

Migration Initialization: It initializes a migrator object with the database connection.
Print Table SQL: It prints the SQL schema of various tables using the print_table_sql() function for the 
following models:
Users
Organization
User
Agent
Bucket
File
AgentFile
AgentBucket

Table Creation (Commented): There are commented lines that seem to be intended for creating tables 
using migrator.create_tables() method for models like Organization, User, Agent, Bucket, File, and 
AgentFile. However, these lines are currently commented out.

Print Statements: Each print_table_sql() call is followed by a semicolon (;), likely for formatting 
purposes.

This script allows for easy inspection of the SQL schema for different database tables by printing their respective SQL definitions. Additionally, it provides functionality for creating tables, although the table creation commands are currently commented out.

"""

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
