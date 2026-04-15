"""Zeek protocol module registry.

Import MODULES to get the dispatcher mapping of log-type name → module instance.
"""

from .conn import ConnModule
from .dns import DnsModule
from .http import HttpModule
from .notice import NoticeModule
from .rdp import RdpModule
from .smb import SmbModule
from .smtp import SmtpModule
from .ssh import SshModule
from .ssl import SslModule
from .weird import WeirdModule

MODULES: dict = {
    "conn": ConnModule(),
    "dns": DnsModule(),
    "http": HttpModule(),
    "ssl": SslModule(),
    "smtp": SmtpModule(),
    "rdp": RdpModule(),
    "smb": SmbModule(),
    "ssh": SshModule(),
    "notice": NoticeModule(),
    "weird": WeirdModule(),
}

__all__ = ["MODULES"]
