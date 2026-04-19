"""Zeek protocol module registry.

Import MODULES to get the dispatcher mapping of log-type name → module instance.
Import MODULES_BY_CATEGORY, CATEGORY_ORDER, CATEGORY_LABELS for web UI grouping.
"""

from collections import defaultdict

from .capture_loss import CaptureLossModule
from .conn import ConnModule
from .dhcp import DhcpModule
from .dnp3 import Dnp3Module
from .dns import DnsModule
from .dpd import DpdModule
from .files import FilesModule
from .ftp import FtpModule
from .http import HttpModule
from .kerberos import KerberosModule
from .modbus import ModbusModule
from .notice import NoticeModule
from .ntlm import NtlmModule
from .ntp import NtpModule
from .pe import PEModule
from .radius import RadiusModule
from .rdp import RdpModule
from .sip import SipModule
from .smb import SmbModule
from .smtp import SmtpModule
from .ssh import SshModule
from .ssl import SslModule
from .suricata_alert import SuricataAlertModule
from .tunnel import TunnelModule
from .weird import WeirdModule
from .x509 import X509Module

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
    "suricata_alert": SuricataAlertModule(),
    "files": FilesModule(),
    "x509": X509Module(),
    "pe": PEModule(),
    "dhcp": DhcpModule(),
    "kerberos": KerberosModule(),
    "ntlm": NtlmModule(),
    "ftp": FtpModule(),
    "radius": RadiusModule(),
    "sip": SipModule(),
    "tunnel": TunnelModule(),
    "ntp": NtpModule(),
    "modbus": ModbusModule(),
    "dnp3": Dnp3Module(),
    "capture_loss": CaptureLossModule(),
    "dpd": DpdModule(),
}

# ---------------------------------------------------------------------------
# Web UI category registry
# ---------------------------------------------------------------------------

CATEGORY_ORDER: list[str] = [
    "alerts",
    "network",
    "web",
    "remote",
    "auth",
    "messaging",
    "files",
    "ot",
    "diagnostic",
]

CATEGORY_LABELS: dict[str, str] = {
    "alerts": "Alerts",
    "network": "Network",
    "web": "Web & TLS",
    "remote": "Remote Access",
    "auth": "Auth & Identity",
    "messaging": "Messaging",
    "files": "Files",
    "ot": "OT / ICS",
    "diagnostic": "Diagnostic",
}

MODULES_BY_CATEGORY: dict[str, list[str]] = defaultdict(list)
for _lt, _mod in MODULES.items():
    MODULES_BY_CATEGORY[_mod.WEB_CATEGORY].append(_lt)

__all__ = ["MODULES", "MODULES_BY_CATEGORY", "CATEGORY_ORDER", "CATEGORY_LABELS"]
