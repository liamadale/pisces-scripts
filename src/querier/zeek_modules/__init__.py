"""Zeek protocol module registry.

Import MODULES to get the dispatcher mapping of log-type name → module instance.
"""

from .conn import ConnModule
from .dns import DnsModule
from .http import HttpModule
from .ssl import SslModule
from .smtp import SmtpModule
from .rdp import RdpModule
from .smb import SmbModule
from .ssh import SshModule
from .notice import NoticeModule
from .weird import WeirdModule

MODULES: dict = {
    "conn":   ConnModule(),
    "dns":    DnsModule(),
    "http":   HttpModule(),
    "ssl":    SslModule(),
    "smtp":   SmtpModule(),
    "rdp":    RdpModule(),
    "smb":    SmbModule(),
    "ssh":    SshModule(),
    "notice": NoticeModule(),
    "weird":  WeirdModule(),
}

__all__ = ["MODULES"]
