"""
NullifierESC
============
Security orchestration service for a web3 VPN + anti-malware platform.
Single-file app by request.

Internal API quick map
----------------------
GET:
- /health
- /nodes
- /events
- /snapshot
- /incidents
- /policies
- /telemetry
- /signatures
- /simulations
- /appendix-notes

POST:
- /node/register
- /node/update
- /session/open
- /session/flag
- /session/close
- /signal/evaluate
- /incident/close
- /policy/update
- /scan/run
- /policy/autotune
- /state/compact

Core domains
------------
- Node registry and health state
- Session lifecycle and malware flags
- Policy pack evaluation (watch/flag/block)
- Incident lifecycle
- Telemetry rollups and maintenance
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Tuple


APP_NAME = "NullifierESC"
APP_VERSION = "1.0.0-nx"
HOST = "127.0.0.1"
PORT = 8794
MAX_EVENTS = 3000

THREAT_FEED_TEXT = """
dns-tunnel-wave-001|dns-tunnel|712|flag|711
dns-tunnel-wave-002|dns-tunnel|719|flag|718
dns-tunnel-wave-003|dns-tunnel|726|flag|724
dns-tunnel-wave-004|dns-tunnel|733|flag|732
dns-tunnel-wave-005|dns-tunnel|740|flag|739
dns-tunnel-wave-006|dns-tunnel|747|flag|746
dns-tunnel-wave-007|dns-tunnel|754|flag|751
dns-tunnel-wave-008|dns-tunnel|761|flag|758
dns-tunnel-wave-009|dns-tunnel|768|flag|763
dns-tunnel-wave-010|dns-tunnel|775|flag|770
proxy-shadow-011|proxy-shadow|782|flag|772
proxy-shadow-012|proxy-shadow|789|flag|776
proxy-shadow-013|proxy-shadow|796|flag|781
proxy-shadow-014|proxy-shadow|803|flag|785
proxy-shadow-015|proxy-shadow|810|flag|789
proxy-shadow-016|proxy-shadow|817|block|805
proxy-shadow-017|proxy-shadow|824|block|812
proxy-shadow-018|proxy-shadow|831|block|819
proxy-shadow-019|proxy-shadow|838|block|826
proxy-shadow-020|proxy-shadow|845|block|833
mesh-ghost-021|mesh-ghost|852|block|841
mesh-ghost-022|mesh-ghost|859|block|847
mesh-ghost-023|mesh-ghost|866|block|853
mesh-ghost-024|mesh-ghost|873|block|860
mesh-ghost-025|mesh-ghost|880|block|868
mesh-ghost-026|mesh-ghost|887|block|875
mesh-ghost-027|mesh-ghost|894|block|882
mesh-ghost-028|mesh-ghost|901|block|890
mesh-ghost-029|mesh-ghost|908|block|898
mesh-ghost-030|mesh-ghost|915|block|905
relay-hop-031|relay-hop|622|watch|610
relay-hop-032|relay-hop|629|watch|615
relay-hop-033|relay-hop|636|watch|620
relay-hop-034|relay-hop|643|watch|626
relay-hop-035|relay-hop|650|watch|631
relay-hop-036|relay-hop|657|watch|636
relay-hop-037|relay-hop|664|watch|641
relay-hop-038|relay-hop|671|watch|646
relay-hop-039|relay-hop|678|watch|651
relay-hop-040|relay-hop|685|watch|656
rebind-loop-041|rebind|702|flag|688
rebind-loop-042|rebind|709|flag|694
rebind-loop-043|rebind|716|flag|700
rebind-loop-044|rebind|723|flag|706
rebind-loop-045|rebind|730|flag|712
rebind-loop-046|rebind|737|flag|718
rebind-loop-047|rebind|744|flag|724
rebind-loop-048|rebind|751|flag|730
rebind-loop-049|rebind|758|flag|736
rebind-loop-050|rebind|765|flag|742
payload-spike-051|payload-spike|802|block|801
payload-spike-052|payload-spike|809|block|806
payload-spike-053|payload-spike|816|block|812
payload-spike-054|payload-spike|823|block|818
payload-spike-055|payload-spike|830|block|824
payload-spike-056|payload-spike|837|block|830
payload-spike-057|payload-spike|844|block|836
payload-spike-058|payload-spike|851|block|842
payload-spike-059|payload-spike|858|block|848
payload-spike-060|payload-spike|865|block|854
ttl-morph-061|ttl-morph|592|watch|580
ttl-morph-062|ttl-morph|599|watch|585
ttl-morph-063|ttl-morph|606|watch|590
ttl-morph-064|ttl-morph|613|watch|595
ttl-morph-065|ttl-morph|620|watch|600
ttl-morph-066|ttl-morph|627|watch|605
ttl-morph-067|ttl-morph|634|watch|610
ttl-morph-068|ttl-morph|641|watch|615
ttl-morph-069|ttl-morph|648|watch|620
ttl-morph-070|ttl-morph|655|watch|625
egress-fork-071|egress-fork|672|watch|661
egress-fork-072|egress-fork|679|watch|666
egress-fork-073|egress-fork|686|watch|671
egress-fork-074|egress-fork|693|watch|676
egress-fork-075|egress-fork|700|flag|682
egress-fork-076|egress-fork|707|flag|688
