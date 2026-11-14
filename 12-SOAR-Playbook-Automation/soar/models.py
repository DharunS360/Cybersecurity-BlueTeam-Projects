"""Core data models shared by every layer."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    CVE = "cve"


class Status(str, Enum):
    OK = "ok"                    # source answered and has data on the indicator
    NOT_FOUND = "not_found"      # source answered: indicator not listed
    ERROR = "error"              # source failed (network/auth/parse) - NOT treated as clean
    RATE_LIMITED = "rate_limited"
    SKIPPED = "skipped"          # no API key / unsupported


@dataclass
class IOC:
    type: IOCType
    value: str
    sources: list[str] = field(default_factory=list)  # where in the alert it was seen

    @property
    def key(self) -> tuple[str, str]:
        return (self.type.value, self.value)


@dataclass
class Finding:
    provider: str
    status: Status
    points: int = 0
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    link: str = ""
    queried_at: str = ""
    cached: bool = False

    @property
    def answered(self) -> bool:
        return self.status in (Status.OK, Status.NOT_FOUND)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d["status"] = Status(d["status"])
        return cls(**d)


@dataclass
class IOCVerdict:
    ioc: IOC
    score: int
    label: str
    answered: int
    applicable: int
    notes: list[str]
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.ioc.type.value,
            "value": self.ioc.value,
            "seen_in": self.ioc.sources,
            "score": self.score,
            "verdict": self.label,
            "sources_answered": self.answered,
            "sources_applicable": self.applicable,
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Alert:
    source: str
    title: str
    input_sha256: str
    iocs: list[IOC]
    skipped: list[dict[str, str]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    severity: str | None = None


@dataclass
class CaseResult:
    case_id: str
    created_at: str
    alert: Alert
    verdicts: list[IOCVerdict]
    score: int
    label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "created_at": self.created_at,
            "source": self.alert.source,
            "title": self.alert.title,
            "severity": self.alert.severity,
            "input_sha256": self.alert.input_sha256,
            "meta": self.alert.meta,
            "overall_score": self.score,
            "overall_verdict": self.label,
            "skipped_indicators": self.alert.skipped,
            "indicators": [v.to_dict() for v in self.verdicts],
        }