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
    """
    Base model for all database models.

    Attributes:
        created_at (DateTimeTZField): The timestamp of when the record was created.
        updated_at (DateTimeTZField): The timestamp of when the record was last updated.
        created_by (TextField): The user who created the record.
        updated_by (TextField): The user who last updated the record.

    Meta:
        database (PostgresqlExtDatabase): The database to use for this model.
    """
    created_at= DateTimeTZField(default=datetime.datetime.now())
    updated_at= DateTimeTZField(default=datetime.datetime.now())
    created_by = TextField(default="SYSTEM")
    updated_by = TextField(default="SYSTEM")

    class Meta:
        database = db


class Organization(BaseModel):
    """
    Model for representing organizations.

    Attributes:
        id (BigAutoField): The primary key of the organization.
        name (TextField): The name of the organization.
        website (TextField): The website URL of the organization.
        details (TextField): Additional details about the organization.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    id = BigAutoField(primary_key=True)
    name = TextField(null=False)
    website = TextField(null=False)
    details = TextField()

    class Meta:
        table_name = "organization"
        schema = "core"


class CoreModel(BaseModel):
    """
    Base model for core entities.

    Attributes:
        id (BigAutoField): The primary key of the entity.
        organization (ForeignKeyField): The organization to which the entity belongs.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    id = BigAutoField(primary_key=True)
    organization = ForeignKeyField(Organization, null=False)

class Users(CoreModel):
    """
    Model for representing users.

    Attributes:
        user_first_name (TextField): The first name of the user.
        user_last_name (TextField): The last name of the user.
        email (TextField): The email address used for login.
        password (TextField): The hashed password of the user.
        access_token (TextField): The access token of the user.
        refresh_token (TextField): The refresh token of the user.
        organization_name (TextField): The name of the organization the user belongs to.
        role (TextField): The role of the user.
        otp (TextField): The one-time password of the user.
        mfa (BooleanField): Flag indicating whether multi-factor authentication is enabled for the user.
        email_valid (BooleanField): Flag indicating whether the email is validated.
        mfa_type (TextField): The type of multi-factor authentication.
        mfa_secret (TextField): The secret key for multi-factor authentication.
        mfa_uri (TextField): The URI for multi-factor authentication.
        otp_expiry (DateTimeField): The expiry timestamp of the one-time password.
        mfa_verified (BooleanField): Flag indicating whether multi-factor authentication is verified.

    Functions:
        hash_password
                Hashes the provided password using MD5.

                Args:
                    password (str): The password to hash.

                Returns:
                    str: The hashed password.
        set_password
                Sets the password by hashing it using MD5

                Args:
                   password (str): The password to set.


    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
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
    """
    Model for representing users in an organization.

    Attributes:
        user_first_name (TextField): The first name of the user.
        user_last_name (TextField): The last name of the user.
        user_id (TextField): The user ID.
        idp_provider (TextField): The IDP provider details.
        is_active (BooleanField): Flag indicating whether the user is active.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
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




