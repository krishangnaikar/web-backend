import logging


class ApplicationLogger:
    def info(msg):
        return logging.getLogger('info_application').info(msg)

    def error(msg):
        return logging.getLogger('error_application').error(msg)

    def debug(msg):
        return logging.getLogger('debug_application').debug(msg)

    def warn(msg):
        return logging.getLogger('warning_application').warn(msg)


class ThirdPartyLogger:
    def info(msg):
        return logging.getLogger('info_third_party').info(msg)

    def error(msg):
        return logging.getLogger('error_third_party').error(msg)

    def debug(msg):
        return logging.getLogger('debug_third_party').debug(msg)

    def warn(msg):
        return logging.getLogger('warning_third_party').warn(msg)


class AuditLogger:
    def info(msg):
        return logging.getLogger('info_audit').info(msg)

    def error(msg):
        return logging.getLogger('error_audit').error(msg)

    def debug(msg):
        return logging.getLogger('debug_audit').debug(msg)

    def warn(msg):
        return logging.getLogger('warning_audit').warn(msg)
