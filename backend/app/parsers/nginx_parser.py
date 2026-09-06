import re
from datetime import datetime
from app.models.event import Event
from app.parsers.base import BaseParser

COMBINED = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/\d\.\d)?" (?P<status>\d{3})')

def parse_ts(value):
    try: return datetime.strptime(value.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError: return None

class NginxParser(BaseParser):
    def matches(self, lines):
        return sum(bool(COMBINED.search(x)) for x in lines[:20]) >= 2
    def parse(self, line):
        m = COMBINED.search(line)
        if not m: return None
        d = m.groupdict()
        return Event(timestamp=parse_ts(d["ts"]), source_ip=d["ip"], method=d["method"], path=d["path"], status_code=int(d["status"]), event_type="http_request", raw_log=line)
