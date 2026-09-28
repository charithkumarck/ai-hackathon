"""
Retrieval over the ATT&CK knowledge base.

Deliberately a self-contained BM25 -- no torch, no embedding service, no vector
DB to stand up before a demo. ATT&CK matching is terminology matching
("failed logon", "kerberos", "scheduled task"), which lexical search is good at,
and the LLM does the final discrimination anyway.

The important property is not the ranking quality, it is that this function is
the ONLY source of candidate technique IDs. The model downstream can rank and
reject them, but it cannot introduce one.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache

from .attack_kb import AttackKB, Technique, get_kb

_TOKEN_RE = re.compile(r"[a-z0-9_]+")

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "for", "on", "with", "by",
    "is", "are", "be", "been", "may", "can", "that", "this", "it", "as", "from",
    "at", "adversary", "adversaries", "attacker", "attackers", "use", "using",
    "used", "via", "such", "other", "their", "them", "these", "also", "which",
    "when", "where", "into", "have", "has", "will", "would", "could", "should",
}

# Security synonym expansion. A rule says "logon failure"; ATT&CK says
# "authentication failure". Cheap bridge, big recall win.
SYNONYMS = {
    "logon": ["login", "authentication", "signin"],
    "login": ["logon", "authentication", "signin"],
    "signin": ["logon", "login", "authentication"],
    "auth": ["authentication", "logon"],
    "failed": ["failure", "unsuccessful", "invalid"],
    "failure": ["failed", "unsuccessful"],
    "password": ["credential", "credentials"],
    "creds": ["credential", "credentials", "password"],
    "mfa": ["multifactor", "authenticator", "2fa"],
    "vpn": ["remote", "external"],
    "powershell": ["script", "command", "interpreter"],
    "cmd": ["command", "shell"],
    "exe": ["executable", "process"],
    "proc": ["process"],
    "dns": ["domain", "resolution"],
    "s3": ["cloud", "storage", "bucket"],
    "iam": ["cloud", "account", "permission"],
    "rdp": ["remote", "desktop", "session"],
    "smb": ["network", "share"],
    "admin": ["administrator", "privileged", "privilege"],
    "priv": ["privilege", "privileged"],
    "escalation": ["privilege"],
    "beacon": ["command", "control", "c2"],
    "c2": ["command", "control"],
    "exfil": ["exfiltration", "transfer"],
    "ransomware": ["encrypt", "impact", "destruction"],
    "impossible": ["anomalous", "unusual"],
    "travel": ["geolocation", "location"],
    "lateral": ["movement", "remote"],
    "persistence": ["persist", "autostart", "boot"],
    "registry": ["regedit", "hive"],
    "token": ["access", "credential"],
    "kerberos": ["ticket", "kerberoasting"],
    "ntlm": ["hash", "credential"],
    "dump": ["dumping", "memory", "credential"],
    "lsass": ["credential", "dumping", "memory"],
    "task": ["scheduled", "job"],
    "service": ["daemon", "systemd"],
    "email": ["mail", "mailbox", "office"],
    "mailbox": ["email", "mail", "collection"],
    "share": ["network", "file"],
    "encrypt": ["encryption", "ransomware"],
    "delete": ["deletion", "removal", "destruction"],
    "clear": ["deletion", "removal", "log"],
}


def tokenize(text: str, expand: bool = False) -> list[str]:
    tokens = [t for t in _TOKEN_RE.findall((text or "").lower()) if t not in STOPWORDS and len(t) > 1]
    if not expand:
        return tokens
    out = list(tokens)
    for tok in tokens:
        out.extend(SYNONYMS.get(tok, []))
    return out


@dataclass
class Candidate:
    technique: Technique
    score: float

    def as_dict(self) -> dict:
        t = self.technique
        return {
            "id": t.id,
            "name": t.name,
            "tactic": t.tactic_names[0] if t.tactic_names else "Unknown",
            "score": round(self.score, 3),
            "is_sub": t.is_sub,
            "parent_id": t.parent_id,
            "description": t.description[:400],
        }


class BM25Index:
    """Textbook BM25 over the ATT&CK technique corpus."""

    K1 = 1.4
    B = 0.75

    def __init__(self, kb: AttackKB):
        self.kb = kb
        self.ids: list[str] = []
        self.docs: list[Counter] = []
        self.lengths: list[int] = []
        self.name_tokens: list[set[str]] = []
        self.df: Counter = Counter()

        for tid, tech in kb.techniques.items():
            tokens = tokenize(tech.search_text())
            counts = Counter(tokens)
            self.ids.append(tid)
            self.docs.append(counts)
            self.lengths.append(len(tokens))
            self.name_tokens.append(set(tokenize(tech.name)))
            for term in counts:
                self.df[term] += 1

        self.n = len(self.docs)
        self.avg_len = (sum(self.lengths) / self.n) if self.n else 0.0
        self.idf = {
            term: math.log(1 + (self.n - freq + 0.5) / (freq + 0.5))
            for term, freq in self.df.items()
        }

    def search(
        self,
        query: str,
        top_k: int = 8,
        restrict_tactics: list[str] | None = None,
        exclude: set[str] | None = None,
    ) -> list[Candidate]:
        q_terms = tokenize(query, expand=True)
        if not q_terms:
            return []
        q_set = set(q_terms)
        exclude = exclude or set()
        want_tactics = set(restrict_tactics) if restrict_tactics else None

        scored: list[Candidate] = []
        for i, tid in enumerate(self.ids):
            if tid in exclude:
                continue
            tech = self.kb.techniques[tid]
            if want_tactics and not (want_tactics & set(tech.tactics)):
                continue
            doc = self.docs[i]
            dl = self.lengths[i] or 1
            score = 0.0
            for term in q_terms:
                tf = doc.get(term)
                if not tf:
                    continue
                idf = self.idf.get(term, 0.0)
                denom = tf + self.K1 * (1 - self.B + self.B * dl / self.avg_len)
                score += idf * (tf * (self.K1 + 1)) / denom
            if score <= 0:
                continue
            # Name boost. A technique whose *title* contains the query's terms
            # ("LSASS", "kerberoasting") is far more likely the answer than one
            # that merely mentions them in a 600-word description.
            # Squared so a *full* name match ("LSASS Memory") is rewarded far
            # more than a partial one ("Domain Controller Authentication"
            # catching the words "domain controller" in passing).
            names = self.name_tokens[i]
            if names:
                overlap = len(names & q_set) / len(names)
                score *= 1 + 1.2 * overlap ** 2
            scored.append(Candidate(tech, score))

        scored.sort(key=lambda c: c.score, reverse=True)
        return scored[:top_k]


@lru_cache(maxsize=1)
def get_index() -> BM25Index:
    return BM25Index(get_kb())
