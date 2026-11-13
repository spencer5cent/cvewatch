#!/usr/bin/env python3
"""Small durable feed helpers for CVEWatch's severity-neutral intelligence lane."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib


UTC = datetime.timezone.utc
SCHEMA_VERSION = 1


def _english_description(cve: dict) -> str:
    rows = cve.get("descriptions") or []
    row = next((item for item in rows if item.get("lang") == "en"), rows[0] if rows else {})
    return str(row.get("value") or "")[:2000]


def _best_cvss(metrics: dict) -> tuple[float, str]:
    best_score, best_vector = 0.0, ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for metric in metrics.get(key, []):
            data = metric.get("cvssData") or {}
            score = float(data.get("baseScore") or 0)
            if score > best_score:
                best_score, best_vector = score, str(data.get("vectorString") or "")
    return best_score, best_vector


def compact_record(cve: dict, *, observed_at: str, poc_urls: list[str]) -> dict | None:
    """Keep enough NVD structure for exact downstream joins, never alert policy."""
    cve_id = str(cve.get("id") or "").upper()
    if not cve_id or str(cve.get("vulnStatus") or "").lower() == "rejected":
        return None
    score, vector = _best_cvss(cve.get("metrics") or {})
    references = []
    for item in cve.get("references") or []:
        url = str(item.get("url") or "").strip()
        if url:
            references.append({"url": url[:1000], "tags": sorted(str(tag) for tag in (item.get("tags") or []))[:12]})
        if len(references) == 40:
            break
    configurations = cve.get("configurations") or []
    row = {
        "cve_id": cve_id,
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or observed_at),
        "vuln_status": str(cve.get("vulnStatus") or ""),
        "description": _english_description(cve),
        "score": score,
        "vector": vector,
        "weaknesses": sorted({
            str(desc.get("value") or "")
            for weakness in (cve.get("weaknesses") or [])
            for desc in (weakness.get("description") or [])
            if desc.get("value")
        })[:20],
        "references": references,
        "poc_refs": sorted(set(poc_urls))[:20],
        "configurations": configurations[:80],
        "cpe_truncated": len(configurations) > 80,
        "observed_at": observed_at,
    }
    digest_source = json.dumps({
        "last_modified": row["last_modified"], "poc_refs": row["poc_refs"],
        "configurations": row["configurations"], "references": row["references"],
    }, sort_keys=True, separators=(",", ":"))
    row["source_digest"] = hashlib.sha256(digest_source.encode()).hexdigest()
    return row


def load_feed(path: str | os.PathLike[str]) -> dict:
    try:
        value = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError, TypeError):
        return {"schema_version": SCHEMA_VERSION, "records": {}}
    if value.get("schema_version") != SCHEMA_VERSION or not isinstance(value.get("records"), dict):
        return {"schema_version": SCHEMA_VERSION, "records": {}}
    return value


def update_feed(path: str | os.PathLike[str], rows: list[dict], *, generated_at: str,
                cursor_end: str, retention_days: int = 7) -> dict:
    """Atomically merge a completed NVD window into a bounded rolling feed."""
    target = pathlib.Path(path)
    existing = load_feed(target)
    records = dict(existing.get("records") or {})
    for row in rows:
        if row and row.get("cve_id"):
            records[str(row["cve_id"])] = row
    cutoff = datetime.datetime.fromisoformat(generated_at.replace("Z", "+00:00")) - datetime.timedelta(days=retention_days)
    kept = {}
    for key, row in records.items():
        try:
            seen = datetime.datetime.fromisoformat(str(row.get("observed_at") or "").replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if seen >= cutoff:
            kept[key] = row
    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "cursor_end": cursor_end,
        "records": kept,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    os.chmod(temporary, 0o640)
    os.replace(temporary, target)
    return document


def nvd_window_start(now: datetime.datetime, requested_hours: int,
                     cursor_end: str, bootstrap_hours: int = 26) -> datetime.datetime:
    """Use a full overnight bootstrap; later runs resume the durable cursor."""
    requested = now - datetime.timedelta(hours=requested_hours)
    if not cursor_end:
        return min(requested, now - datetime.timedelta(hours=bootstrap_hours))
    try:
        cursor = datetime.datetime.fromisoformat(cursor_end.replace("Z", "+00:00"))
        if cursor.tzinfo is None:
            cursor = cursor.replace(tzinfo=UTC)
        cursor = max(cursor - datetime.timedelta(minutes=5), now - datetime.timedelta(days=7))
        return min(requested, cursor)
    except (TypeError, ValueError):
        return min(requested, now - datetime.timedelta(hours=bootstrap_hours))
