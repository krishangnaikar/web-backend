import datetime
from peewee import *
from dotenv import load_dotenv
from os import environ
from playhouse.postgres_ext import *
import hashlib

load_dotenv()
PG_HOST = environ.get("POSTGRES_HOST_NAME", default="localhost")
POSTGRES_USER_NAME = environ.get("POSTGRES_USER_NAME", default="postgres")
POSTGRES_USER_PASSWORD = environ.get("POSTGRES_USER_PASSWORD", default="password")
POSTGRES_DB_NAME = environ.get("POSTGRES_DB_NAME",default="truenil")
#initialize connection to database
db = PostgresqlExtDatabase("truenil", user=POSTGRES_USER_NAME, password=POSTGRES_USER_PASSWORD, host=PG_HOST)


class BaseModel(Model):
    created_at= DateTimeTZField(default=datetime.datetime.now())
    updated_at= DateTimeTZField(default=datetime.datetime.now())
    created_by = TextField(default="SYSTEM")
    updated_by = TextField(default="SYSTEM")

    class Meta:
        database = db


class Organization(BaseModel):
    id = BigAutoField(primary_key=True)
    name = TextField(null=False)
    website = TextField(null=False)
    details = TextField()

    class Meta:
        table_name = "organization"
        schema = "core"


class CoreModel(BaseModel):
    id = BigAutoField(primary_key=True)
    organization = ForeignKeyField(Organization, null=False)

class Users(CoreModel):
    user_first_name = TextField(null=False)
    user_last_name = TextField(null=False)
    # Email address used for login
    email = TextField(null=False)
    password = TextField(null=True)
    access_token = TextField(default=None, null=True)
    refresh_token = TextField(default=None, null=True)
    organization_name = TextField(null=False)
    role = TextField(null=False)
    otp = TextField(null=True)
    mfa = BooleanField(default=False)
    email_valid = BooleanField(default=False)
    mfa_type = TextField(default=None, null=True)
    mfa_secret = TextField(default=None, null=True)
    mfa_uri = TextField(default=None, null=True)
    otp_expiry = DateTimeField(default=datetime.datetime.now())
    mfa_verified = BooleanField(default=False)
    # Values would refer to IDP Provider details.
    # e.g. Google, AWS, Microsoft, Apple, ETC
    @staticmethod
    def hash_password(password):
        """
        Hash the provided password using MD5.
        """
        md5 = hashlib.md5()
        md5.update(password.encode('utf-8'))
        return md5.hexdigest()

    def set_password(self, password):
        """
        Set the password by hashing it using MD5.
        """
        self.password = self.hash_password(password)

    class Meta:
        table_name = "users"
        schema = "core"

class User(CoreModel):
    user_first_name = TextField(null=False)
    user_last_name = TextField(null=False)
    # Email address used for login
    user_id= TextField(null=False)
    # Values would refer to IDP Provider details.
    # e.g. Google, AWS, Microsoft, Apple, ETC
    idp_provider = TextField(null=True)
    is_active = BooleanField(default=True, null=False)
    class Meta:
        table_name = "organization_user"
        schema = "core"


user_org_unique_idx = User.index(
    User.organization,
    User.user_id,
    unique=True)
User.add_index(user_org_unique_idx)




