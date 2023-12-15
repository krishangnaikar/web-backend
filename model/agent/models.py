import datetime
from peewee import *
from dotenv import load_dotenv
from os import environ
from playhouse.postgres_ext import *

from model.core.models import CoreModel

AGENT_INITIALIZED = "initialized"


class Agent(CoreModel):
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
    bucket_key = TextField(null=False)
    # values will be the following (in lowercase)
    # aws, gcp, azure, digitalocean, misc
    cloud = TextField(null=False)

    class Meta:
        table_name = "bucket"
        schema = "agent"


class File(CoreModel):
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
    agent = ForeignKeyField(Agent, null=False)
    token = ForeignKeyField(AgentToken, null=False)

    class Meta:
        table_name = "agent_token_audit"
        schema = "agent"

class UserFilePermission(CoreModel):
    file = ForeignKeyField(File,null=False)
    user = TextField(null=False)
    permissions = JSONField(null=False)

    class Meta:
        table_name = "user_file_permissions"
        schema = "agent"

class AgentFileAudit(CoreModel):
    agent = ForeignKeyField(Agent, null=False)
    user_name = TextField(null=False)
    user_email= TextField(null=False)
    file_name = TextField(null=False)
    operation = TextField(null=False)

    class Meta:
        table_name = "agent_file_audit"
        schema = "agent"