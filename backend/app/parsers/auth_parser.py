import re
from datetime import datetime
from app.models.event import Event
from app.parsers.base import BaseParser

FAILED = re.compile(r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Failed password for (?:invalid user )?(?P<user>[\w._-]+) from (?P<ip>[0-9a-fA-F:.]+)")
INVALID = re.compile(r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Invalid user (?P<user>[\w._-]+) from (?P<ip>[0-9a-fA-F:.]+)")
ACCEPTED = re.compile(r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Accepted \w+ for (?P<user>[\w._-]+) from (?P<ip>[0-9a-fA-F:.]+)")

def parse_ts(value: str):
    try:
        return datetime.strptime(f"{datetime.utcnow().year} {value}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

class AuthParser(BaseParser):
    def matches(self, lines):
        sample = "\n".join(lines[:30]).lower()
        return "sshd" in sample or "failed password" in sample

    def parse(self, line):
        for pattern, event_type in ((FAILED, "auth_failure"), (INVALID, "auth_failure"), (ACCEPTED, "auth_success")):
            m = pattern.search(line)
            if m:
                d = m.groupdict()
                return Event(timestamp=parse_ts(d["ts"]), source_ip=d["ip"], username=d["user"], event_type=event_type, raw_log=line)
        return None
