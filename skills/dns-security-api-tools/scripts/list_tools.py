"""Print secret-free Agent schemas from the installed package."""
import json
from dns_security_api import DNS_TOOL_DEFINITIONS
print(json.dumps(DNS_TOOL_DEFINITIONS, indent=2))
