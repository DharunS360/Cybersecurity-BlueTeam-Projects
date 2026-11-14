"""Pipeline: ingest -> select sources -> parallel enrich (cache, rate limit) -> score -> audit."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .config import Settings
from .http import HttpClient, ProviderError
from .models import IOC, Alert, CaseResult, Finding, IOCType, Status
from .providers import build_providers
from .providers.base import Provider
from .scoring import aggregate, overall
from .store import Store, utcnow

PRIORITY = {IOCType.HASH: 0, IOCType.URL: 1, IOCType.IP: 2, IOCType.CVE: 3, IOCType.DOMAIN: 4, IOCType.EMAIL: 5}


def new_case_id() -> str:
    return f"CASE-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


class Engine:
    def __init__(self, settings: Settings, store: Store | None = None,
                 providers: list[Provider] | None = None, http: HttpClient | None = None) -> None:
        self.settings = settings
        self.http = http or HttpClient(settings.http_timeout)
        self.store = store or Store(settings.db_path)
        self.providers = providers if providers is not None else build_providers(settings, self.http)

    # ---------------------------------------------------------------- single query
    def query(self, provider: Provider, ioc: IOC, use_cache: bool = True) -> Finding:
        """One provider x one indicator. Never raises: failures become explicit findings."""
        if not provider.enabled:
            return Finding(provider.name, Status.SKIPPED, reason="no API key configured", queried_at=utcnow())
        ttl = self.settings.ttl_hash_hours if ioc.type is IOCType.HASH else self.settings.ttl_default_hours
        if use_cache and provider.cacheable:
            hit = self.store.cache_get(provider.name, ioc.type.value, ioc.value, ttl)
            if hit:
                return hit
        try:
            finding = provider.lookup(ioc)
        except ProviderError as exc:
            status = Status.RATE_LIMITED if exc.kind == "rate_limit" else Status.ERROR
            finding = Finding(provider.name, status, reason=f"{exc.kind}: {exc.message}")
        except Exception as exc:     # a buggy provider must never take the whole case down
            finding = Finding(provider.name, Status.ERROR, reason=f"internal: {type(exc).__name__}: {exc}"[:200])
        finding.queried_at = utcnow()
        if provider.cacheable and finding.answered:
            self.store.cache_put(provider.name, ioc.type.value, ioc.value, finding)
        return finding

    # ---------------------------------------------------------------- full case
    def analyze(self, alert: Alert, actor: str = "analyst", use_cache: bool = True) -> CaseResult:
        case_id, created = new_case_id(), utcnow()
        iocs = sorted(alert.iocs, key=lambda i: (PRIORITY[i.type], i.value))
        if len(iocs) > self.settings.max_iocs:
            for dropped in iocs[self.settings.max_iocs:]:
                alert.skipped.append({"type": dropped.type.value, "value": dropped.value,
                                      "reason": f"over SOAR_MAX_IOCS limit ({self.settings.max_iocs})"})
            iocs = iocs[: self.settings.max_iocs]
        self.store.audit(actor, "case.created", case_id, {
            "source": alert.source, "title": alert.title, "input_sha256": alert.input_sha256,
            "iocs": len(iocs), "skipped": len(alert.skipped)})

        tasks = [(ioc, p) for ioc in iocs for p in self.providers if p.applies_to(ioc)]
        results: dict[tuple, Finding] = {}

        def run(task: tuple[IOC, Provider]) -> tuple[tuple, Finding, float]:
            ioc, prov = task
            t0 = time.monotonic()
            return (ioc.key, prov.name), self.query(prov, ioc, use_cache), (time.monotonic() - t0) * 1000

        with ThreadPoolExecutor(max_workers=self.settings.max_workers) as pool:
            for key, finding, ms in pool.map(run, tasks):
                results[key] = finding
                self.store.audit(actor, "enrich.query", case_id, {
                    "provider": key[1], "ioc": key[0][1], "ioc_type": key[0][0], "status": finding.status.value,
                    "points": finding.points, "cached": finding.cached, "ms": round(ms)})

        verdicts = []
        for ioc in iocs:
            findings = [results[(ioc.key, p.name)] for p in self.providers if (ioc.key, p.name) in results]
            verdicts.append(aggregate(ioc, findings))
        score, label = overall(verdicts)

        result = CaseResult(case_id, created, alert, verdicts, score, label)
        self.store.audit(actor, "case.verdict", case_id, {"score": score, "verdict": label})
        self.store.save_case(case_id, created, alert.source, alert.title, alert.input_sha256,
                             label, score, result.to_dict())
        return result