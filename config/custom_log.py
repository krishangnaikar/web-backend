"""
A file containing a single dictionary
The dictionary  log_config  is a dictionary that configures logging for different parts of an application. Here's an explanation of its structure:

-  version: The version of the logging configuration. In this case, it's set to  1.
-  disable_existing_loggers: Whether to disable existing loggers. It's set to  False, meaning existing loggers will not be disabled.
-  formatters: This section defines various formatters that specify the format of log messages.
  -  basic,  basic2,  basic3,  default: These are different formatters defined with specific formats for log messages. They include timestamp, log level, and message content.
-  handlers: Handlers define where log records are output. There are several handlers defined here:
  -  default: A handler that streams log messages to sys. stderr.
  - Handlers prefixed with  debug_handler_application_stderr,  info_handler_application_stderr, etc.: These handlers specify different log levels (DEBUG, INFO, WARN, ERROR) for log messages related to the application, third-party components, and audit logs. The output log messages to sys. stdout or sys. stderr based on the log level.
-  loggers: Loggers are entities used to emit log messages. Different loggers are configured with different handlers and log levels.
  -  default: The default logger with the default handler and log level set to DEBUG.
  - Loggers prefixed with  debug_application,  info_application, etc.: These loggers are specifically configured for different components of the application, third-party components, and audit logs. They use corresponding handlers and log levels.

Overall, this configuration sets up logging for various components of the application, allowing different log levels and output streams for different parts of the system.
"""
log_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "basic": {
            "format": "[%(asctime)s] [APPLOG] [%(levelname)s] : %(message)s"
        },
        "basic2": {
            "format": "[%(asctime)s] [THPLOG] [%(levelname)s] : %(message)s"
        },
        "basic3": {
            "format": "[%(asctime)s] [AUDLOG] [%(levelname)s] : %(message)s"
        },
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "format": "[%(asctime)s] [APPLOG] [%(levelname)s] : %(message)s"
        },

    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "debug_handler_application_stderr": {
            "class": "logging.StreamHandler",
            "formatter": "basic",
            "level": "DEBUG",
            "stream": "ext://sys.stdout"
        },
        "info_handler_application_stderr": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "basic",
            "stream": "ext://sys.stdout"
        },
        "warning_handler_application_stderr": {
            "class": "logging.StreamHandler",
            "level": "WARN",
            "formatter": "basic",
            "stream": "ext://sys.stdout"
        },
        "error_handler_application_stderr": {
            "class": "logging.StreamHandler",
            "level": "ERROR",
            "formatter": "basic",
            "stream": "ext://sys.stderr"
        },
        "debug_handler_third_party_stderr": {
            "class": "logging.StreamHandler",
            "formatter": "basic2",
            "level": "DEBUG",
            "stream": "ext://sys.stdout"
        },
        "info_handler_third_party_stderr": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "basic2",
            "stream": "ext://sys.stdout"
        },
        "warning_handler_third_party_stderr": {
            "class": "logging.StreamHandler",
            "level": "WARN",
            "formatter": "basic2",
            "stream": "ext://sys.stdout"
        },
        "error_handler_third_party_stderr": {
            "class": "logging.StreamHandler",
            "level": "ERROR",
            "formatter": "basic2",
            "stream": "ext://sys.stderr"
        },
        "debug_handler_audit_log_stderr": {
            "class": "logging.StreamHandler",
            "formatter": "basic3",
            "level": "DEBUG",
            "stream": "ext://sys.stdout"
        },
        "info_handler_audit_stderr": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "basic3",
            "stream": "ext://sys.stdout"
        },
        "warning_handler_audit_stderr": {
            "class": "logging.StreamHandler",
            "level": "WARN",
            "formatter": "basic3",
            "stream": "ext://sys.stdout"
        },
        "error_handler_audit_stderr": {
            "class": "logging.StreamHandler",
            "level": "ERROR",
            "formatter": "basic3",
            "stream": "ext://sys.stderr"
        }
    },
    "loggers": {
        "default": {
            "handlers": [
                "default"
            ],
            "level": "DEBUG"
        },
        "debug_application": {
            "handlers": [
                "debug_handler_application_stderr"
            ],
            "level": "DEBUG"
        },
        "info_application": {
            "handlers": [
                "info_handler_application_stderr"
            ],
            "level": "INFO"
        },
        "warning_application": {
            "handlers": [
                "warning_handler_application_stderr"
            ],
            "level": "WARN"
        },
        "error_application": {
            "handlers": [
                "error_handler_application_stderr"
            ],
            "level": "ERROR"
        },
        "debug_third_party": {
            "handlers": [
                "debug_handler_third_party_stderr"
            ],
            "level": "DEBUG"
        },
        "info_third_party": {
            "handlers": [
                "info_handler_third_party_stderr"
            ],
            "level": "INFO"
        },
        "warning_third_party": {
            "handlers": [
                "warning_handler_third_party_stderr"
            ],
            "level": "WARN"
        },
        "error_third_party": {
            "handlers": [
                "error_handler_third_party_stderr"
            ],
            "level": "ERROR"
        },
        "debug_audit": {
            "handlers": [
                "debug_handler_audit_log_stderr"
            ],
            "level": "DEBUG"
        },
        "info_audit": {
            "handlers": [
                "info_handler_audit_stderr"
            ],
            "level": "INFO"
        },
        "warning_audit": {
            "handlers": [
                "warning_handler_audit_stderr"
            ],
            "level": "WARN"
        },
        "error_audit": {
            "handlers": [
                "error_handler_audit_stderr"
            ],
            "level": "ERROR"
        }
    },
}
