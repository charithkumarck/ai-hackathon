"""
Detection-rule parser.

Turns a pasted rule in any supported SIEM dialect into a small structured IR.
Two jobs:

  1. Give the retrieval step clean signal instead of raw syntax.
  2. Be the security boundary. A pasted rule is UNTRUSTED INPUT heading for an
     LLM prompt, so comments (the natural place to hide "ignore previous
     instructions") are stripped here and never reach the model. The model sees
     the IR, not the raw text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

LANGUAGE_SIGNATURES: list[tuple[str, list[str]]] = [
    ("Sigma", [r"^\s*title:\s", r"^\s*detection:\s*$", r"\blogsource:\s"]),
    ("SPL", [r"\bindex\s*=", r"\|\s*stats\b", r"\|\s*tstats\b", r"\|\s*eval\b", r"\bsourcetype\s*="]),
    ("KQL", [r"\|\s*summarize\b", r"\|\s*where\b", r"\bSigninLogs\b", r"\bSecurityEvent\b",
             r"\bDeviceProcessEvents\b", r"\bAuditLogs\b", r"\bbin\s*\(", r"\bago\s*\("]),
    ("YARA-L", [r"\brule\s+\w+\s*\{", r"\$e\d*\.metadata", r"\bevents:\s*$", r"\bmatch:\s*$",
                r"\bcondition:\s*$", r"\budm\b"]),
    ("EQL", [r"\bsequence\s+by\b", r"\bprocess\s+where\b", r"\bnetwork\s+where\b"]),
]

COMMENT_PATTERNS = [
    (re.compile(r"```.*?```", re.S), "fenced block"),
    (re.compile(r"/\*.*?\*/", re.S), "block comment"),
    (re.compile(r"(?m)^\s*//.*$"), "line comment"),
    (re.compile(r"(?m)^\s*#(?!\s*\w+:).*$"), "hash comment"),
    (re.compile(r"(?m)\s+//.*$"), "trailing comment"),
    (re.compile(r"<!--.*?-->", re.S), "html comment"),
]

# Phrases that have no business inside a detection rule. Presence means someone
# is trying to talk to the model, not write a query.
INJECTION_MARKERS = [
    "ignore previous", "ignore all previous", "ignore the above", "disregard",
    "system prompt", "you are now", "new instructions", "override",
    "report this as", "always respond", "confidence 100", "full coverage",
    "act as", "forget everything", "print your", "reveal your",
]

# ---------------------------------------------------------------------------
# Data-source fingerprints -> plain-English telemetry + domain
# ---------------------------------------------------------------------------

SOURCE_FINGERPRINTS: list[tuple[str, str, str]] = [
    # (regex, human label, domain)
    (r"signinlogs|index\s*=\s*\"?authentication|wineventlog:security|4625|4624|okta|auth0|"
     r"aadsignin|identity\b|ldap|kerberos|azuread|entra", "authentication / identity provider logs", "Identity"),
    (r"auditlogs|directoryaudit|iam\b|rolemanagement|group_?modification|useradd",
     "directory / IAM audit logs", "Identity"),
    (r"deviceprocessevents|sysmon|4688|process_?creation|edr|crowdstrike|defender|"
     r"winlogbeat|proc\b|image_?path|commandline", "endpoint process telemetry", "Endpoint"),
    (r"devicefileevents|file_?event|filemod|fim\b", "endpoint file telemetry", "Endpoint"),
    (r"devicenetworkevents|netflow|firewall|zeek|bro\b|pcap|proxy|dns_?log|"
     r"network_?traffic|conn\.log", "network / flow logs", "Network"),
    (r"cloudtrail|guardduty|gcp_?audit|azureactivity|s3\b|ec2\b|iam_?policy|"
     r"storage_?bucket|kubernetes|k8s", "cloud control-plane logs", "Cloud"),
    (r"exchange|o365|officeactivity|mailbox|emailevents|messagetrace",
     "email / collaboration logs", "Cloud"),
    (r"registry|reg_?key|regmod", "endpoint registry telemetry", "Endpoint"),
]

# ---------------------------------------------------------------------------
# Indicator lexicon
#
# BM25 cannot know that port 445 means SMB, or that event 1102 means the audit
# log was wiped. A detection engineer reads those instantly. This table injects
# the same knowledge into the retrieval query so the right technique reaches the
# candidate pool -- recall here is the ceiling on the whole system, because the
# model can only choose from what retrieval found.
# ---------------------------------------------------------------------------

INDICATOR_HINTS: list[tuple[str, str]] = [
    (r"\b445\b|\bsmb\b|admin\$|c\$", "smb windows admin shares remote services lateral movement"),
    (r"\b3389\b|\brdp\b|remote desktop", "remote desktop protocol session hijacking lateral movement"),
    (r"\b5985\b|\b5986\b|winrm|wsman", "windows remote management lateral movement"),
    (r"\b22\b.*ssh|\bssh\b", "ssh remote services lateral movement"),
    (r"4625|logon.?fail|authentication.?fail", "failed logon brute force password guessing"),
    (r"4624", "successful logon valid accounts"),
    (r"4720", "create account local account persistence"),
    (r"4732|group.?modification|add.*administrators", "account manipulation group membership privilege escalation"),
    (r"4698|schtasks|scheduled.?task", "scheduled task job persistence"),
    (r"1102|wevtutil|clear-?eventlog", "clear windows event logs indicator removal defense impairment"),
    (r"4769.*0x17|kerberoast", "kerberoasting service ticket credential access"),
    (r"4768|golden.?ticket|krbtgt", "steal or forge kerberos tickets golden ticket"),
    (r"vssadmin|shadow.?cop|wbadmin|bcdedit", "inhibit system recovery data destruction impact"),
    (r"lsass", "os credential dumping lsass memory"),
    (r"putbucketacl|public-?read|bucket.?acl", "data from cloud storage publicly accessible resource"),
    (r"500121|mfa.?deni|push.?deni", "multi factor authentication request generation fatigue"),
    (r"inboxrule|forwardto|redirectto", "email forwarding rule collection exfiltration"),
    (r"-enc\b|encodedcommand|frombase64string", "powershell obfuscated files or information command interpreter"),
    (r"currentversion\\\\?run|run.?key|startup.?folder", "registry run keys startup folder boot autostart persistence"),
    (r"7z\.exe|rar\.exe|winrar|\btar\b|\bzip\b", "archive collected data via utility collection"),
    (r"len\(query\)|qlen|dns.*>.*\d{2,}", "dns application layer protocol exfiltration over alternative protocol"),
    (r"beacon|jitter|avg\(bytes", "application layer protocol web protocols command and control"),
    (r"rundll32|regsvr32|mshta", "signed binary proxy execution system binary proxy"),
    (r"net\s+group|net\s+user|whoami|nltest", "account discovery domain account system owner discovery"),
    (r"defender|crowdstrike|sentinelone|disable.*antivirus", "disable or modify tools defense impairment"),
    (r"unattend\.xml|id_rsa|\.aws/credentials|credential.*file", "credentials in files unsecured credentials"),
    (r"guest|external.*user", "valid accounts cloud accounts"),
    (r"imap4|pop3|legacy.?auth", "valid accounts brute force legacy authentication"),
    (r"encrypt|ransom|\.locked", "data encrypted for impact ransomware"),
    (r"impossible.?travel|anomalous.?location|d?c(?:ount)?\((?:location|country|city|geo)",
     "valid accounts cloud accounts anomalous login location"),
    (r"4740|lockout|account.?locked", "brute force password guessing account lockout credential access"),
    (r"(?:modified|filemod|filecreate|encrypted).{0,40}>\s*\d{3,}|mass.?file",
     "data encrypted for impact ransomware file destruction"),
    (r"50057|disabled.?account", "valid accounts disabled account brute force"),
]


def indicator_hints(text: str) -> list[str]:
    low = text.lower()
    return [hint for pattern, hint in INDICATOR_HINTS if re.search(pattern, low)]


ACTION_SUCCESS = re.compile(
    r"(action\s*=\s*[\"']?success|resulttype\s*=\s*[\"']?0|eventid\s*=\s*[\"']?4624|"
    r"outcome\s*=\s*[\"']?success|status\s*=\s*[\"']?(success|allow)|logon_?success)", re.I)
ACTION_FAILURE = re.compile(
    r"(action\s*=\s*[\"']?fail|resulttype\s*!=\s*[\"']?0|eventid\s*=\s*[\"']?4625|"
    r"outcome\s*=\s*[\"']?fail|status\s*=\s*[\"']?(fail|deny|block)|logon_?fail|"
    r"error|invalid|denied)", re.I)

THRESHOLD_RE = re.compile(r"(?:where|having|\|\s*where)?\s*([a-z_][\w.]*)\s*(>=|>|<=|<)\s*(\d+)", re.I)
# Three shapes, because a missed time window becomes a false "no time window
# declared" blind spot, which is worse than saying nothing:
#   span=1h / earliest=-24h / timeframe: 15m   -> direct
#   bin(TimeGenerated, 1h) / bin_auto(x, 5m)   -> second argument
#   ago(1h)                                    -> only argument
TIMEWINDOW_PATTERNS = [
    re.compile(r"(?:span|earliest|latest|timeframe|window|over|within)\s*[=:(\s]\s*-?(\d+)\s*([smhd])\b", re.I),
    re.compile(r"\bbin(?:_auto)?\s*\([^,()]*,\s*-?(\d+)\s*([smhd])\b", re.I),
    re.compile(r"\bago\s*\(\s*-?(\d+)\s*([smhd])\b", re.I),
]
GROUPBY_RE = re.compile(r"(?:by|group by|partition by)\s+([\w.,\s]+?)(?:\||\n|$)", re.I)
AGG_RE = re.compile(r"\b(count|dcount|distinct_count|sum|avg|max|min|values)\s*\(?", re.I)


@dataclass
class ParsedRule:
    language: str
    language_confidence: str
    raw_length: int
    sanitized: str
    data_source: str
    domain: str
    aggregation: str | None
    group_by: list[str]
    threshold: dict[str, Any] | None
    time_window: str | None
    observes_success: bool
    observes_failure: bool
    fields: list[str]
    is_natural_language: bool
    hints: list[str] = field(default_factory=list)
    security_findings: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary_for_model(self) -> str:
        """The only representation of the user's input the LLM ever sees."""
        lines = [
            f"language: {self.language}",
            f"telemetry: {self.data_source}",
            f"security domain: {self.domain}",
            f"observes successful events: {self.observes_success}",
            f"observes failed/denied events: {self.observes_failure}",
        ]
        if self.aggregation:
            lines.append(f"aggregation: {self.aggregation}")
        if self.group_by:
            lines.append(f"grouped by: {', '.join(self.group_by)}")
        if self.threshold:
            t = self.threshold
            lines.append(f"threshold: {t['field']} {t['op']} {t['value']}")
        lines.append(f"time window: {self.time_window or 'NONE DECLARED'}")
        if self.fields:
            lines.append(f"fields referenced: {', '.join(self.fields[:15])}")
        lines.append("--- sanitized query text ---")
        lines.append(self.sanitized[:2000])
        return "\n".join(lines)


def _strip_comments(text: str) -> tuple[str, list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    cleaned = text
    for pattern, label in COMMENT_PATTERNS:
        for match in pattern.findall(cleaned):
            snippet = match if isinstance(match, str) else str(match)
            low = snippet.lower()
            if any(marker in low for marker in INJECTION_MARKERS):
                findings.append({
                    "type": "prompt_injection",
                    "location": label,
                    "detail": snippet.strip()[:180],
                })
        cleaned = pattern.sub(" ", cleaned)
    return cleaned, findings


def _scan_body_for_injection(text: str) -> list[dict[str, str]]:
    findings = []
    low = text.lower()
    for marker in INJECTION_MARKERS:
        if marker in low:
            idx = low.index(marker)
            findings.append({
                "type": "prompt_injection",
                "location": "rule body",
                "detail": text[max(0, idx - 30): idx + 90].strip()[:180],
            })
            break
    return findings


def detect_language(text: str) -> tuple[str, str]:
    scores: dict[str, int] = {}
    for lang, patterns in LANGUAGE_SIGNATURES:
        hits = sum(1 for p in patterns if re.search(p, text, re.I | re.M))
        if hits:
            scores[lang] = hits
    if not scores:
        words = len(text.split())
        if words and words < 40 and not re.search(r"[|{}=]", text):
            return "Natural language", "high"
        return "Unknown", "low"
    best = max(scores, key=lambda k: scores[k])
    confidence = "high" if scores[best] >= 2 else "medium"
    return best, confidence


def _classify_source(text: str) -> tuple[str, str]:
    low = text.lower()
    for pattern, label, domain in SOURCE_FINGERPRINTS:
        if re.search(pattern, low):
            return label, domain
    return "unclassified log source", "Endpoint"


def _extract_fields(text: str) -> list[str]:
    raw = re.findall(r"\b([a-z_][a-z0-9_]{2,})\s*(?:=|==|!=|=~|:)", text, re.I)
    noise = {"index", "sourcetype", "source", "rule", "title", "author", "status",
             "level", "type", "and", "not", "let", "where"}
    seen: list[str] = []
    for f in raw:
        fl = f.lower()
        if fl not in noise and fl not in seen:
            seen.append(fl)
    return seen[:20]


def parse_rule(text: str) -> ParsedRule:
    original = text or ""
    sanitized, findings = _strip_comments(original)
    findings.extend(_scan_body_for_injection(sanitized))
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized).strip()

    language, confidence = detect_language(sanitized)
    data_source, domain = _classify_source(sanitized)

    agg_match = AGG_RE.search(sanitized)
    aggregation = agg_match.group(1).lower() if agg_match else None

    group_by: list[str] = []
    gb = GROUPBY_RE.search(sanitized)
    if gb:
        group_by = [g.strip() for g in gb.group(1).split(",") if g.strip()][:6]

    threshold = None
    th = THRESHOLD_RE.search(sanitized)
    if th:
        threshold = {"field": th.group(1), "op": th.group(2), "value": int(th.group(3))}

    time_window = None
    for pattern in TIMEWINDOW_PATTERNS:
        tw = pattern.search(sanitized)
        if not tw:
            continue
        unit = {"s": "second", "m": "minute", "h": "hour", "d": "day"}[tw.group(2).lower()]
        plural = "" if tw.group(1) == "1" else "s"
        time_window = f"{tw.group(1)} {unit}{plural}"
        break

    return ParsedRule(
        language=language,
        language_confidence=confidence,
        raw_length=len(original),
        sanitized=sanitized,
        data_source=data_source,
        domain=domain,
        aggregation=aggregation,
        group_by=group_by,
        threshold=threshold,
        time_window=time_window,
        observes_success=bool(ACTION_SUCCESS.search(sanitized)),
        observes_failure=bool(ACTION_FAILURE.search(sanitized)),
        fields=_extract_fields(sanitized),
        is_natural_language=(language == "Natural language"),
        hints=indicator_hints(sanitized),
        security_findings=findings,
    )
