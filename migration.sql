CREATE SCHEMA IF NOT EXISTS "core";
CREATE SCHEMA IF NOT EXISTS "agent";
CREATE TABLE IF NOT EXISTS "core"."users" (
  "id" BIGSERIAL NOT NULL PRIMARY KEY,
  "created_at" TIMESTAMPTZ NOT NULL,
  "updated_at" TIMESTAMPTZ NOT NULL,
  "created_by" TEXT NOT NULL,
  "updated_by" TEXT NOT NULL,
  "organization_id" BIGINT NOT NULL,
  "user_first_name" TEXT NOT NULL,
  "user_last_name" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "password" TEXT,
  "access_token" TEXT,
  "refresh_token" TEXT,
  "organization_name" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "otp" TEXT,
  "mfa" BOOLEAN NOT NULL,
  "email_valid" BOOLEAN NOT NULL,
  "mfa_type" TEXT,
  "mfa_secret" TEXT,
  "mfa_uri" TEXT,
  "otp_expiry" TIMESTAMP NOT NULL,
  FOREIGN KEY ("organization_id") REFERENCES "core"."organization" ("id")
)
;
CREATE TABLE IF NOT EXISTS "core"."organization" (
  "id" BIGSERIAL NOT NULL PRIMARY KEY,
  "created_at" TIMESTAMPTZ NOT NULL,
  "updated_at" TIMESTAMPTZ NOT NULL,
  "created_by" TEXT NOT NULL,
  "updated_by" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "website" TEXT NOT NULL,
  "details" TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS "core"."organization_user" (
  "id" BIGSERIAL NOT NULL PRIMARY KEY,
  "created_at" TIMESTAMPTZ NOT NULL,
  "updated_at" TIMESTAMPTZ NOT NULL,
  "created_by" TEXT NOT NULL,
  "updated_by" TEXT NOT NULL,
  "organization_id" BIGINT NOT NULL,
  "user_first_name" TEXT NOT NULL,
  "user_last_name" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  "idp_provider" TEXT,
  "is_active" BOOLEAN NOT NULL,
  FOREIGN KEY ("organization_id") REFERENCES "core"."organization" ("id")
);
CREATE TABLE IF NOT EXISTS "agent"."agent" (
  "id" BIGSERIAL NOT NULL PRIMARY KEY,
  "created_at" TIMESTAMPTZ NOT NULL,
  "updated_at" TIMESTAMPTZ NOT NULL,
  "created_by" TEXT NOT NULL,
  "updated_by" TEXT NOT NULL,
  "organization_id" BIGINT NOT NULL,
  "uuid" UUID NOT NULL,
  "version" TEXT NOT NULL,
  "health_status" TEXT NOT NULL,
  "last_ping" TIMESTAMPTZ NOT NULL,
  "ip_address" TEXT NOT NULL,
  "host_name" TEXT NOT NULL,
  "running_as_user_name" TEXT,
  "environment_settings" TEXT,
  "metadata" JSON,
  FOREIGN KEY ("organization_id") REFERENCES "core"."organization" ("id")
);
CREATE TABLE IF NOT EXISTS "agent"."bucket" (
  "id" BIGSERIAL NOT NULL PRIMARY KEY,
  "created_at" TIMESTAMPTZ NOT NULL,
  "updated_at" TIMESTAMPTZ NOT NULL,
  "created_by" TEXT NOT NULL,
  "updated_by" TEXT NOT NULL,
  "organization_id" BIGINT NOT NULL,
  "bucket_key" TEXT NOT NULL,
  "cloud" TEXT NOT NULL,
  FOREIGN KEY ("organization_id") REFERENCES "core"."organization" ("id")
);
CREATE TABLE IF NOT EXISTS "agent"."file" (
  "id" BIGSERIAL NOT NULL PRIMARY KEY,
  "created_at" TIMESTAMPTZ NOT NULL,
  "updated_at" TIMESTAMPTZ NOT NULL,
  "created_by" TEXT NOT NULL,
  "updated_by" TEXT NOT NULL,
  "organization_id" BIGINT NOT NULL,
  "bucket_id" BIGINT NOT NULL,
  "file_path" TEXT NOT NULL,
  "encryption_status" TEXT NOT NULL,
  "storage_type" TEXT NOT NULL,
  "file_type" TEXT NOT NULL,
  "compression_type" TEXT NOT NULL,
  FOREIGN KEY ("organization_id") REFERENCES "core"."organization" ("id"),
  FOREIGN KEY ("bucket_id") REFERENCES "agent"."bucket" ("id")
);
CREATE TABLE IF NOT EXISTS "agent"."agent_file" (
  "id" BIGSERIAL NOT NULL PRIMARY KEY,
  "created_at" TIMESTAMPTZ NOT NULL,
  "updated_at" TIMESTAMPTZ NOT NULL,
  "created_by" TEXT NOT NULL,
  "updated_by" TEXT NOT NULL,
  "organization_id" BIGINT NOT NULL,
  "agent_id" BIGINT NOT NULL,
  "file_id" BIGINT NOT NULL,
  FOREIGN KEY ("organization_id") REFERENCES "core"."organization" ("id"),
  FOREIGN KEY ("agent_id") REFERENCES "agent"."agent" ("id"),
  FOREIGN KEY ("file_id") REFERENCES "agent"."file" ("id")
);
CREATE TABLE IF NOT EXISTS "agent_bucket" (
  "id" BIGSERIAL NOT NULL PRIMARY KEY,
  "created_at" TIMESTAMPTZ NOT NULL,
  "updated_at" TIMESTAMPTZ NOT NULL,
  "created_by" TEXT NOT NULL,
  "updated_by" TEXT NOT NULL,
  "organization_id" BIGINT NOT NULL,
  "agent_id" BIGINT NOT NULL,
  "bucket_id" BIGINT NOT NULL,
  FOREIGN KEY ("organization_id") REFERENCES "core"."organization" ("id"),
  FOREIGN KEY ("agent_id") REFERENCES "agent"."agent" ("id"),
  FOREIGN KEY ("bucket_id") REFERENCES "agent"."bucket" ("id")
);
