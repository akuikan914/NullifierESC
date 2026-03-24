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
egress-fork-077|egress-fork|714|flag|694
egress-fork-078|egress-fork|721|flag|700
egress-fork-079|egress-fork|728|flag|706
egress-fork-080|egress-fork|735|flag|712
probe-swarm-081|probe-swarm|642|watch|631
probe-swarm-082|probe-swarm|649|watch|636
probe-swarm-083|probe-swarm|656|watch|641
probe-swarm-084|probe-swarm|663|watch|646
probe-swarm-085|probe-swarm|670|watch|651
probe-swarm-086|probe-swarm|677|watch|656
probe-swarm-087|probe-swarm|684|watch|661
probe-swarm-088|probe-swarm|691|watch|666
probe-swarm-089|probe-swarm|698|watch|671
probe-swarm-090|probe-swarm|705|flag|676
route-smear-091|route-smear|616|watch|602
route-smear-092|route-smear|623|watch|607
route-smear-093|route-smear|630|watch|612
route-smear-094|route-smear|637|watch|617
route-smear-095|route-smear|644|watch|622
route-smear-096|route-smear|651|watch|627
route-smear-097|route-smear|658|watch|632
route-smear-098|route-smear|665|watch|637
route-smear-099|route-smear|672|watch|642
route-smear-100|route-smear|679|watch|647
"""

THREAT_FEED_TEXT_EXTENDED = """
grid-101|dns-tunnel|681|watch|652
grid-102|dns-tunnel|688|watch|657
grid-103|dns-tunnel|695|watch|662
grid-104|dns-tunnel|702|flag|668
grid-105|dns-tunnel|709|flag|674
grid-106|dns-tunnel|716|flag|680
grid-107|dns-tunnel|723|flag|686
grid-108|dns-tunnel|730|flag|692
grid-109|dns-tunnel|737|flag|698
grid-110|dns-tunnel|744|flag|704
grid-111|dns-tunnel|751|flag|710
grid-112|dns-tunnel|758|flag|716
grid-113|dns-tunnel|765|flag|722
grid-114|dns-tunnel|772|flag|728
grid-115|dns-tunnel|779|flag|734
grid-116|proxy-shadow|786|flag|740
grid-117|proxy-shadow|793|flag|746
grid-118|proxy-shadow|800|block|752
grid-119|proxy-shadow|807|block|758
grid-120|proxy-shadow|814|block|764
grid-121|proxy-shadow|821|block|770
grid-122|proxy-shadow|828|block|776
grid-123|proxy-shadow|835|block|782
grid-124|proxy-shadow|842|block|788
grid-125|proxy-shadow|849|block|794
grid-126|proxy-shadow|856|block|800
grid-127|mesh-ghost|863|block|806
grid-128|mesh-ghost|870|block|812
grid-129|mesh-ghost|877|block|818
grid-130|mesh-ghost|884|block|824
grid-131|mesh-ghost|891|block|830
grid-132|mesh-ghost|898|block|836
grid-133|mesh-ghost|905|block|842
grid-134|mesh-ghost|912|block|848
grid-135|mesh-ghost|919|block|854
grid-136|mesh-ghost|926|block|860
grid-137|relay-hop|603|watch|588
grid-138|relay-hop|610|watch|593
grid-139|relay-hop|617|watch|598
grid-140|relay-hop|624|watch|603
grid-141|relay-hop|631|watch|608
grid-142|relay-hop|638|watch|613
grid-143|relay-hop|645|watch|618
grid-144|relay-hop|652|watch|623
grid-145|relay-hop|659|watch|628
grid-146|relay-hop|666|watch|633
grid-147|relay-hop|673|watch|638
grid-148|relay-hop|680|watch|643
grid-149|relay-hop|687|watch|648
grid-150|relay-hop|694|watch|653
grid-151|relay-hop|701|flag|658
grid-152|relay-hop|708|flag|663
grid-153|relay-hop|715|flag|668
grid-154|relay-hop|722|flag|673
grid-155|relay-hop|729|flag|678
grid-156|relay-hop|736|flag|683
grid-157|ttl-morph|590|watch|570
grid-158|ttl-morph|597|watch|575
grid-159|ttl-morph|604|watch|580
grid-160|ttl-morph|611|watch|585
grid-161|ttl-morph|618|watch|590
grid-162|ttl-morph|625|watch|595
grid-163|ttl-morph|632|watch|600
grid-164|ttl-morph|639|watch|605
grid-165|ttl-morph|646|watch|610
grid-166|ttl-morph|653|watch|615
grid-167|ttl-morph|660|watch|620
grid-168|ttl-morph|667|watch|625
grid-169|ttl-morph|674|watch|630
grid-170|ttl-morph|681|watch|635
grid-171|ttl-morph|688|watch|640
grid-172|ttl-morph|695|watch|645
grid-173|egress-fork|702|flag|650
grid-174|egress-fork|709|flag|656
grid-175|egress-fork|716|flag|662
grid-176|egress-fork|723|flag|668
grid-177|egress-fork|730|flag|674
grid-178|egress-fork|737|flag|680
grid-179|egress-fork|744|flag|686
grid-180|egress-fork|751|flag|692
grid-181|egress-fork|758|flag|698
grid-182|egress-fork|765|flag|704
grid-183|egress-fork|772|flag|710
grid-184|egress-fork|779|flag|716
grid-185|egress-fork|786|flag|722
grid-186|egress-fork|793|flag|728
grid-187|egress-fork|800|block|734
grid-188|egress-fork|807|block|740
grid-189|egress-fork|814|block|746
grid-190|egress-fork|821|block|752
grid-191|egress-fork|828|block|758
grid-192|egress-fork|835|block|764
grid-193|probe-swarm|642|watch|630
grid-194|probe-swarm|649|watch|635
grid-195|probe-swarm|656|watch|640
grid-196|probe-swarm|663|watch|645
grid-197|probe-swarm|670|watch|650
grid-198|probe-swarm|677|watch|655
grid-199|probe-swarm|684|watch|660
grid-200|probe-swarm|691|watch|665
grid-201|probe-swarm|698|watch|670
grid-202|probe-swarm|705|flag|675
grid-203|probe-swarm|712|flag|680
grid-204|probe-swarm|719|flag|685
grid-205|probe-swarm|726|flag|690
grid-206|probe-swarm|733|flag|695
grid-207|probe-swarm|740|flag|700
grid-208|probe-swarm|747|flag|705
grid-209|probe-swarm|754|flag|710
grid-210|probe-swarm|761|flag|715
grid-211|probe-swarm|768|flag|720
grid-212|route-smear|575|watch|560
grid-213|route-smear|582|watch|565
grid-214|route-smear|589|watch|570
grid-215|route-smear|596|watch|575
grid-216|route-smear|603|watch|580
grid-217|route-smear|610|watch|585
grid-218|route-smear|617|watch|590
grid-219|route-smear|624|watch|595
grid-220|route-smear|631|watch|600
grid-221|route-smear|638|watch|605
grid-222|route-smear|645|watch|610
grid-223|route-smear|652|watch|615
grid-224|route-smear|659|watch|620
grid-225|route-smear|666|watch|625
grid-226|route-smear|673|watch|630
grid-227|route-smear|680|watch|635
grid-228|route-smear|687|watch|640
grid-229|route-smear|694|watch|645
grid-230|route-smear|701|flag|650
grid-231|route-smear|708|flag|655
grid-232|route-smear|715|flag|660
grid-233|route-smear|722|flag|665
grid-234|route-smear|729|flag|670
grid-235|route-smear|736|flag|675
grid-236|route-smear|743|flag|680
grid-237|route-smear|750|flag|685
grid-238|route-smear|757|flag|690
grid-239|route-smear|764|flag|695
grid-240|route-smear|771|flag|700
"""


def _now() -> int:
    return int(time.time())


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rand_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(10)}"


def _risk_bucket(score: int) -> str:
    if score >= 900:
        return "critical"
    if score >= 700:
        return "high"
    if score >= 450:
        return "medium"
    return "low"


def _parse_feed_rows(raw: str) -> List[Tuple[str, str, int, str, int]]:
    out: List[Tuple[str, str, int, str, int]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) != 5:
            continue
        sid, family, conf, action, score = parts
        try:
            out.append((sid, family, int(conf), action, int(score)))
        except ValueError:
            continue
    return out


@dataclass
class NodeProfile:
    node_id: str
    region: str
    endpoint: str
    quality: int
    health: int
    online: bool = True
    malware_bps: int = 0
    updated_at: int = field(default_factory=_now)


@dataclass
class SessionProfile:
    session_id: str
    account: str
    node_id: str
    started_at: int
    expires_at: int
    collateral_wei: int
    flagged: bool = False
    closed: bool = False
    closed_at: int = 0
    close_reason: str = ""


@dataclass
class EventRow:
    event_id: str
    ts: int
    channel: str
    severity: str
    payload: Dict[str, object]


@dataclass
class ThreatSignature:
    signature_id: str
    family: str
    confidence: int
    action: str
    score: int


@dataclass
class IncidentTicket:
    ticket_id: str
    created_at: int
    severity: str
    account: str
    session_id: str
    signal: str
    status: str
    notes: str = ""


class NullifierCore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.started_at = _now()
        self.nodes: Dict[str, NodeProfile] = {}
        self.sessions: Dict[str, SessionProfile] = {}
        self.events: List[EventRow] = []
        self.allowlist: Dict[str, int] = {}
        self.blocklist: Dict[str, int] = {}
        self.signatures: Dict[str, ThreatSignature] = {}
        self.incidents: Dict[str, IncidentTicket] = {}
