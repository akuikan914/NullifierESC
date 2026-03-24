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
        self.policy_pack: Dict[str, Dict[str, object]] = {}
        self.scan_jobs: Dict[str, Dict[str, object]] = {}
        self.telemetry_rollups: List[Dict[str, object]] = []
        self._seed_defaults()
        self._seed_policy_pack()
        self._seed_signatures()

    def _seed_defaults(self) -> None:
        presets = [
            ("EU-West", "wss://eu-west.nx-relay.net/v1", 880, 950, 130),
            ("US-East", "wss://us-east.nx-relay.net/v1", 840, 915, 160),
            ("AP-SG", "wss://ap-sg.nx-relay.net/v1", 795, 870, 250),
        ]
        for region, endpoint, quality, health, malware_bps in presets:
            node_id = _rand_id("node")
            self.nodes[node_id] = NodeProfile(
                node_id=node_id,
                region=region,
                endpoint=endpoint,
                quality=quality,
                health=health,
                malware_bps=malware_bps,
            )
        self._push("core", "low", {"message": "defaults-seeded", "node_count": len(self.nodes)})

    def _seed_policy_pack(self) -> None:
        policy_rows = [
            ("dns-jitter-guard", 710, "flag", 120),
            ("relay-entropy-fence", 650, "watch", 140),
            ("socket-rebind-block", 780, "block", 90),
            ("egress-cluster-shield", 690, "watch", 100),
            ("payload-surge-nullifier", 845, "block", 60),
            ("route-echo-limiter", 580, "watch", 150),
            ("path-drift-sentinel", 620, "watch", 160),
            ("host-fingerprint-lock", 760, "flag", 80),
            ("anti-c2-whisper", 890, "block", 45),
            ("mirror-proxy-tracer", 600, "watch", 170),
        ]
        for name, threshold, action, cooldown in policy_rows:
            self.policy_pack[name] = {
                "name": name,
                "threshold": threshold,
                "action": action,
                "cooldown_sec": cooldown,
                "enabled": True,
            }
        self._push("core", "low", {"message": "policy-pack-seeded", "policy_count": len(self.policy_pack)})

    def _seed_signatures(self) -> None:
        rows = [
            ("sig_dns_tunnel_arc", "dns-tunnel", 740, "flag", 740),
            ("sig_mirror_hop_flux", "relay-hop", 695, "watch", 670),
            ("sig_payload_spike_q1", "payload-spike", 860, "block", 860),
            ("sig_shadow_proxy_h7", "proxy-shadow", 810, "flag", 800),
            ("sig_socket_loop_m2", "socket-loop", 770, "flag", 760),
            ("sig_rebind_wisp_44", "rebind", 790, "block", 790),
            ("sig_ttl_morph_ff", "ttl-morph", 630, "watch", 640),
            ("sig_egress_fork_k9", "egress-fork", 720, "flag", 730),
            ("sig_probe_swarm_17", "probe-swarm", 680, "watch", 650),
            ("sig_mesh_ghost_55", "mesh-ghost", 910, "block", 920),
        ]
        for signature_id, family, confidence, action, score in rows:
            self.signatures[signature_id] = ThreatSignature(signature_id, family, confidence, action, score)
        for signature_id, family, confidence, action, score in _parse_feed_rows(THREAT_FEED_TEXT):
            self.signatures[signature_id] = ThreatSignature(signature_id, family, confidence, action, score)
        for signature_id, family, confidence, action, score in _parse_feed_rows(THREAT_FEED_TEXT_EXTENDED):
            self.signatures[signature_id] = ThreatSignature(signature_id, family, confidence, action, score)
        self._push("core", "low", {"message": "signature-pack-seeded", "signature_count": len(self.signatures)})

    def policy_autotune(self) -> Dict[str, object]:
        with self._lock:
            incidents_open = sum(1 for i in self.incidents.values() if i.status != "closed")
            delta = 0
            if incidents_open >= 18:
                delta = -35
            elif incidents_open >= 9:
                delta = -20
            elif incidents_open >= 4:
                delta = -10
            changed = []
            for name, row in self.policy_pack.items():
                before = int(row["threshold"])
                next_threshold = max(450, min(930, before + delta))
                if next_threshold != before:
                    row["threshold"] = next_threshold
                    changed.append({"name": name, "before": before, "after": next_threshold})
            self._push("policy", "medium" if delta < 0 else "low", {"action": "autotune", "delta": delta, "changed": len(changed)})
            return {"ok": True, "delta": delta, "changed": changed}

    def compact_state(self) -> Dict[str, object]:
        with self._lock:
            cutoff = _now() - 3600 * 24 * 3
            before_inc = len(self.incidents)
            self.incidents = {k: v for k, v in self.incidents.items() if v.created_at >= cutoff or v.status != "closed"}
            before_scan = len(self.scan_jobs)
            self.scan_jobs = {k: v for k, v in self.scan_jobs.items() if int(v.get("at", 0)) >= cutoff}
            self.telemetry_rollups = [r for r in self.telemetry_rollups if int(r.get("at", 0)) >= cutoff]
            self._push(
                "maintenance",
                "low",
                {
                    "action": "compact-state",
                    "incidents_before": before_inc,
                    "incidents_after": len(self.incidents),
                    "scan_jobs_before": before_scan,
                    "scan_jobs_after": len(self.scan_jobs),
                },
            )
            return {
                "ok": True,
                "incidents_before": before_inc,
                "incidents_after": len(self.incidents),
                "scan_jobs_before": before_scan,
                "scan_jobs_after": len(self.scan_jobs),
            }

    def _push(self, channel: str, severity: str, payload: Dict[str, object]) -> None:
        row = EventRow(event_id=_rand_id("evt"), ts=_now(), channel=channel, severity=severity, payload=payload)
        self.events.append(row)
        if len(self.events) > MAX_EVENTS:
            self.events = self.events[-MAX_EVENTS:]

    def _severity_score(self, severity: str) -> int:
        table = {"low": 250, "medium": 520, "high": 760, "critical": 930}
        return table.get(severity, 250)

    def health(self) -> Dict[str, object]:
        with self._lock:
            active_sessions = sum(1 for s in self.sessions.values() if not s.closed)
            flagged_sessions = sum(1 for s in self.sessions.values() if s.flagged and not s.closed)
            node_online = sum(1 for n in self.nodes.values() if n.online)
            score = (node_online * 95) - (flagged_sessions * 12)
            incident_open = sum(1 for i in self.incidents.values() if i.status != "closed")
            return {
                "app": APP_NAME,
                "version": APP_VERSION,
                "uptime_seconds": _now() - self.started_at,
                "nodes_total": len(self.nodes),
                "nodes_online": node_online,
                "sessions_total": len(self.sessions),
                "sessions_active": active_sessions,
                "sessions_flagged": flagged_sessions,
                "risk_score": max(0, min(1000, score)),
                "risk_bucket": _risk_bucket(max(0, min(1000, score))),
                "incidents_open": incident_open,
                "policy_count": len(self.policy_pack),
                "signature_count": len(self.signatures),
            }

    def list_nodes(self) -> List[Dict[str, object]]:
        with self._lock:
            rows = []
            for node in self.nodes.values():
                rows.append(
                    {
                        "node_id": node.node_id,
                        "region": node.region,
                        "endpoint": node.endpoint,
                        "quality": node.quality,
                        "health": node.health,
                        "malware_bps": node.malware_bps,
                        "online": node.online,
                        "updated_at": node.updated_at,
                    }
                )
            return rows

    def register_node(self, region: str, endpoint: str, quality: int, health: int, malware_bps: int) -> Dict[str, object]:
        with self._lock:
            node_id = _rand_id("node")
            row = NodeProfile(
                node_id=node_id,
                region=region.strip(),
                endpoint=endpoint.strip(),
                quality=max(0, min(1000, quality)),
                health=max(0, min(1000, health)),
                malware_bps=max(0, min(10000, malware_bps)),
            )
            self.nodes[node_id] = row
            self._push("node", "low", {"action": "register", "node_id": node_id})
            return {"ok": True, "node_id": node_id}

    def update_node(self, node_id: str, patch: Dict[str, object]) -> Dict[str, object]:
        with self._lock:
            node = self.nodes.get(node_id)
            if not node:
                return {"ok": False, "error": "node-not-found"}
            if "quality" in patch:
                node.quality = max(0, min(1000, int(patch["quality"])))
            if "health" in patch:
                node.health = max(0, min(1000, int(patch["health"])))
            if "malware_bps" in patch:
                node.malware_bps = max(0, min(10000, int(patch["malware_bps"])))
            if "online" in patch:
                node.online = bool(patch["online"])
            node.updated_at = _now()
            self._push("node", "low", {"action": "update", "node_id": node_id})
            return {"ok": True, "node_id": node_id}

    def open_session(self, account: str, node_id: str, ttl_sec: int, collateral_wei: int) -> Dict[str, object]:
        with self._lock:
            node = self.nodes.get(node_id)
            if not node or not node.online:
                return {"ok": False, "error": "node-offline-or-missing"}
            ttl = max(30, min(28800, ttl_sec))
            collateral = max(1_000_000_000_000_000, min(2_000_000_000_000_000_000, collateral_wei))
            sid = _rand_id("ses")
            session = SessionProfile(
                session_id=sid,
                account=account,
                node_id=node_id,
                started_at=_now(),
                expires_at=_now() + ttl,
                collateral_wei=collateral,
            )
            self.sessions[sid] = session
            self._push("session", "low", {"action": "open", "session_id": sid, "node_id": node_id})
            return {"ok": True, "session_id": sid}

    def evaluate_signal(self, account: str, session_id: str, signal: str, intensity: int) -> Dict[str, object]:
        with self._lock:
            score = max(0, min(1000, intensity))
            action = "watch"
            matched = []
            for p in self.policy_pack.values():
                if not p["enabled"]:
                    continue
                if score >= int(p["threshold"]):
                    matched.append(p["name"])
                    if p["action"] == "block":
                        action = "block"
                    elif p["action"] == "flag" and action != "block":
                        action = "flag"
            severity = _risk_bucket(score)
            self._push(
                "signal",
                severity,
                {
                    "action": action,
                    "account": account,
                    "session_id": session_id,
                    "signal": signal[:80],
                    "intensity": score,
                    "matched_policies": matched,
                },
            )
            if action in ("flag", "block") and session_id in self.sessions:
                self.sessions[session_id].flagged = True
            if action == "block":
                self.blocklist[account] = _now()
            if action in ("flag", "block"):
                ticket_id = _rand_id("inc")
                self.incidents[ticket_id] = IncidentTicket(
                    ticket_id=ticket_id,
                    created_at=_now(),
                    severity=severity,
                    account=account,
                    session_id=session_id,
                    signal=signal[:80],
                    status="open",
                    notes=f"auto:{action}",
                )
            return {"ok": True, "action": action, "severity": severity, "matched_policies": matched}

    def close_session(self, session_id: str, reason: str) -> Dict[str, object]:
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return {"ok": False, "error": "session-not-found"}
            if session.closed:
                return {"ok": False, "error": "already-closed"}
            session.closed = True
            session.closed_at = _now()
            session.close_reason = reason[:120]
            self._push("session", "low", {"action": "close", "session_id": session_id, "reason": reason[:60]})
            return {"ok": True, "session_id": session_id}
