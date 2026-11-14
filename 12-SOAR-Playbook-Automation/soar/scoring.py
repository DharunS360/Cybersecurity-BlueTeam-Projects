"""Explainable risk scoring.

score = sum of points awarded by each source that ANSWERED, capped at 100.
Every point is traceable to a source + reason, and the verdict states how many
sources actually responded, so "Not Flagged" is never mistaken for "Clean".
"""
from __future__ import annotations

from .models import IOC, Finding, IOCType, IOCVerdict, Status

BANDS = ((70, "Malicious"), (40, "Suspicious"), (10, "Low Risk"), (0, "Not Flagged"))
NO_ENRICHMENT = {IOCType.EMAIL: "email addresses are extracted for context; their domains are enriched"}


def label_for(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "Not Flagged"


def aggregate(ioc: IOC, findings: list[Finding]) -> IOCVerdict:
    applicable = [f for f in findings if f.status is not Status.SKIPPED]
    answered = [f for f in applicable if f.answered]
    score = min(100, sum(f.points for f in answered))
    notes: list[str] = []

    if not findings:
        label = "Not Enriched"
        notes.append(NO_ENRICHMENT.get(ioc.type, "no provider supports this indicator type"))
    elif not answered:
        label = "Unknown"
        notes.append("no source returned an answer - this is NOT a clean result")
        score = 0
    else:
        label = label_for(score)
        benign = [f for f in answered if f.evidence.get("benign")]
        if benign and score < 40:
            names = ", ".join(f.provider for f in benign)
            residual = [f"{f.provider} +{f.points}" for f in answered if f.points and not f.evidence.get("benign")]
            label, score = "Known Benign", 0
            notes.append(f"marked benign by {names}" + (f"; weak residual signals ignored ({', '.join(residual)})" if residual else ""))
        elif benign:
            notes.append(f"CONFLICT: {', '.join(f.provider for f in benign)} say benign but other sources flag it - review manually")
        if label == "Not Flagged" and len(answered) < 2:
            notes.append("only one source answered - low confidence, do not treat as clean")
        flagged = [f for f in answered if f.points >= 40]
        if len(flagged) >= 2:
            notes.append(f"corroborated by {len(flagged)} independent sources")
    failed = [f for f in applicable if not f.answered]
    if failed:
        notes.append("sources that did not answer: " + ", ".join(f"{f.provider} ({f.status.value})" for f in failed))
    skipped = [f for f in findings if f.status is Status.SKIPPED]
    if skipped:
        notes.append("not queried (no API key): " + ", ".join(f.provider for f in skipped))

    return IOCVerdict(ioc, score, label, len(answered), len(applicable), notes, findings)


def overall(verdicts: list[IOCVerdict]) -> tuple[int, str]:
    scored = [v for v in verdicts if v.label not in ("Not Enriched",)]
    if not scored:
        return 0, "Unknown"
    top = max(scored, key=lambda v: v.score)
    if top.label == "Unknown":
        return 0, "Unknown"
    return top.score, top.label