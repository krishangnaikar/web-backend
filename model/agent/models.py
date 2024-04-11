import datetime
from peewee import *
from dotenv import load_dotenv
from os import environ
from playhouse.postgres_ext import *

from model.core.models import CoreModel

AGENT_INITIALIZED = "initialized"


class Agent(CoreModel):
    """
    Represents an agent entity.

    Attributes:
        uuid (UUIDField): Unique identifier for the agent.
        version (TextField): Version of the agent.
        health_status (TextField): Current health status of the agent.
        last_ping (DateTimeTZField): Timestamp of the last ping from the agent.
        ip_address (TextField): IP address of the agent.
        host_name (TextField): Hostname of the machine where the agent is running.
        running_as_user_name (TextField): Name of the user under which the agent is running.
        environment_settings (TextField): Environment settings and their values.
        metadata (JSONField): Unstructured metadata in JSON format.
        agent_state (TextField): Current state of the agent.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    uuid = UUIDField(null=False)
    version = TextField(null=False)
    health_status = TextField(null=False, default=AGENT_INITIALIZED)
    last_ping = DateTimeTZField(default=datetime.datetime.now(tz=datetime.timezone.utc))
    ip_address = TextField(null=False)
    host_name = TextField(null=False)
    # The Host User Name under which the agent is running on the host
    running_as_user_name = TextField(null=True)
    """
    List of environment variables, settings, and their values. 
    Any password related values will be `masked` by the agent before transmitting to the backend
    """
    environment_settings = TextField(null=True)
    # Unstructured Metadata in JSON form. This would store OS information, and miscellaneous ones
    metadata = JSONField(null=True)
    agent_state = TextField(null=False)

    class Meta:
        table_name = "agent"
        schema = "agent"


class Bucket(CoreModel):
    """
    Represents a bucket entity.

    Attributes:
        bucket_key (TextField): Key of the bucket.
        cloud (TextField): Cloud provider associated with the bucket.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    bucket_key = TextField(null=False)
    # values will be the following (in lowercase)
    # aws, gcp, azure, digitalocean, misc
    cloud = TextField(null=False)

    class Meta:
        table_name = "bucket"
        schema = "agent"


class File(CoreModel):
    """
    Represents a file entity.

    Attributes:
        bucket (ForeignKeyField): ForeignKeyField to Bucket model.
        file_path (TextField): Path of the file.
        encryption_status (TextField): Encryption status of the file.
        storage_type (TextField): Storage type of the file.
        file_type (TextField): Type of the file.
        compression_type (TextField): Compression type of the file.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    bucket = ForeignKeyField(Bucket, null=False)
    file_path = TextField(null=False)
    """ 
    Values in lowercase: 
    1. yes
    2. no
    3. unknown
    """
    encryption_status = TextField(null=False)
    """ 
    Values in lower case will be one of the following
    1. aws
    2. gcp
    3. azure
    4. local
    5. samba-share
    """
    storage_type = TextField(null=False)
    """
    Values in lowercase will be one of the following
    1. fasta
    2. bam
    3. bigwig
    4. bed
    5. fastq
    6. vcf
    """
    file_type = TextField(null=False)
    """
    Values will be one of the following
    1. zip
    2. gz
    3. tar
    4. uncompressed
    5. unknown
    """
    compression_type = TextField(null=False)

    class Meta:
        table_name = "file"
        schema = "agent"


class AgentFile(CoreModel):
    """
    Represents a many-to-many relationship between Agent and File models.

    Attributes:
        agent (ForeignKeyField): ForeignKeyField to Agent model.
        file (ForeignKeyField): ForeignKeyField to File model.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    agent = ForeignKeyField(Agent, null=False)
    file = ForeignKeyField(File, null=False)

    class Meta:
        table_name = "agent_file"
        schema = "agent"


agent_file_unique_idx = AgentFile.index(
    AgentFile.agent,
    AgentFile.file,
    unique=True)
AgentFile.add_index(agent_file_unique_idx)

class AgentBucket(CoreModel):
    """
    Represents a many-to-many relationship between Agent and Bucket models.

    Attributes:
        agent (ForeignKeyField): ForeignKeyField to Agent model.
        bucket (ForeignKeyField): ForeignKeyField to Bucket model.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    agent = ForeignKeyField(Agent, null=False)
    bucket = ForeignKeyField(Bucket, null=False)

    class Meta:
        table_name = "agent_bucket"
        schema = "agent"


agent_bucket_unique_idx = AgentBucket.index(
    AgentBucket.agent,
    AgentBucket.bucket,
    unique=True)
AgentBucket.add_index(agent_bucket_unique_idx)


class AgentMetrics(CoreModel):
    """
    Represents agent metrics.

    Attributes:
        agent (ForeignKeyField): ForeignKeyField to Agent model.
        metric_name (TextField): Name of the metric.
        metric_value (DoubleField): Value of the metric.
        process_name (TextField): Name of the process (optional).

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    agent = ForeignKeyField(Agent, null=False)
    """
    metric_name is one of the below. Exact case
        cpu_usage
        number_of_vcpu
        max_memory
        memory_used
        disk_space
        free_space
        network_connectivity
        response_time
        error_rate
    """
    metric_name = TextField(null=False)
    metric_value = DoubleField(null=False)
    # Optional field
    process_name = TextField(null=True)

    class Meta:
        table_name = "agent_metrics"
        schema = "agent"


class AgentToken(CoreModel):
    """
    Represents an agent token.

    Attributes:
        token (TextField): Token value.
        is_active (BooleanField): Indicates if the token is active.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    token = TextField(null=False)
    is_active = BooleanField(default=True, null=False)

    class Meta:
        table_name = "agent_token"
        schema = "agent"


agent_token_unique_idx = AgentToken.index(
    AgentToken.token,
    unique=True)
AgentToken.add_index(agent_token_unique_idx)


class AgentTokenAudit(CoreModel):
    """
    Represents agent token audit records.

    Attributes:
        agent (ForeignKeyField): ForeignKeyField to Agent model.
        token (ForeignKeyField): ForeignKeyField to AgentToken model.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    agent = ForeignKeyField(Agent, null=False)
    token = ForeignKeyField(AgentToken, null=False)

    class Meta:
        table_name = "agent_token_audit"
        schema = "agent"

class UserFilePermission(CoreModel):
    """
    Represents user file permissions.

    Attributes:
        file (ForeignKeyField): ForeignKeyField to File model.
        user (TextField): User name.
        permissions (JSONField): Permissions in JSON format.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    file = ForeignKeyField(File,null=False)
    user = TextField(null=False)
    permissions = JSONField(null=False)

    class Meta:
        table_name = "user_file_permissions"
        schema = "agent"

class AgentFileAudit(CoreModel):
    """
    Represents audit records of file operations performed by agents.

    Attributes:
        agent (ForeignKeyField): ForeignKeyField to Agent model.
        user_name (TextField): User name associated with the operation.
        user_email (TextField): User email associated with the operation.
        file_name (TextField): Name of the file involved in the operation.
        operation (TextField): Type of operation performed.

    Meta:
        table_name (str): Name of the database table.
        schema (str): Schema of the database table.
    """
    agent = ForeignKeyField(Agent, null=False)
    user_name = TextField(null=False)
    user_email= TextField(null=False)
    file_name = TextField(null=False)
    operation = TextField(null=False)

    class Meta:
        table_name = "agent_file_audit"
        schema = "agent"