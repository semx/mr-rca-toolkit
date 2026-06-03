"""Incident correlation and RCA draft generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def parse_ts(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True, slots=True)
class IncidentEvent:
    incident_id: str
    service: str
    started_at: str
    summary: str
    deploys: tuple[dict[str, Any], ...] = ()
    logs: tuple[dict[str, Any], ...] = ()
    traces: tuple[dict[str, Any], ...] = ()
    owners: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IncidentEvent":
        return cls(
            incident_id=str(payload.get("incident_id", "")),
            service=payload["service"],
            started_at=payload["started_at"],
            summary=payload.get("summary", ""),
            deploys=tuple(payload.get("deploys", [])),
            logs=tuple(payload.get("logs", [])),
            traces=tuple(payload.get("traces", [])),
            owners=tuple(payload.get("owners", [])),
        )


@dataclass(frozen=True, slots=True)
class RCADraft:
    incident_id: str
    service: str
    summary: str
    confidence: str
    timeline: tuple[str, ...]
    suspected_causes: tuple[str, ...]
    evidence: tuple[str, ...]
    immediate_actions: tuple[str, ...]
    owners: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "service": self.service,
            "summary": self.summary,
            "confidence": self.confidence,
            "timeline": list(self.timeline),
            "suspected_causes": list(self.suspected_causes),
            "evidence": list(self.evidence),
            "immediate_actions": list(self.immediate_actions),
            "owners": list(self.owners),
        }


class RCABuilder:
    """Correlate deploys, logs, and traces into an RCA draft."""

    def build(self, incident: IncidentEvent) -> RCADraft:
        started_at = parse_ts(incident.started_at)
        related_deploys = self._related_deploys(incident, started_at)
        error_logs = self._error_logs(incident)
        trace_symptoms = self._trace_symptoms(incident)

        timeline = self._timeline(incident, related_deploys, error_logs, trace_symptoms)
        causes = self._causes(related_deploys, error_logs, trace_symptoms)
        evidence = self._evidence(related_deploys, error_logs, trace_symptoms)
        actions = self._actions(related_deploys, error_logs, trace_symptoms)
        confidence = self._confidence(related_deploys, error_logs, trace_symptoms)

        return RCADraft(
            incident_id=incident.incident_id,
            service=incident.service,
            summary=incident.summary,
            confidence=confidence,
            timeline=tuple(timeline),
            suspected_causes=tuple(causes),
            evidence=tuple(evidence),
            immediate_actions=tuple(actions),
            owners=incident.owners,
        )

    def _related_deploys(
        self,
        incident: IncidentEvent,
        started_at: datetime,
    ) -> list[dict[str, Any]]:
        related = []
        for deploy in incident.deploys:
            if deploy.get("service") != incident.service:
                continue
            deployed_at = parse_ts(deploy["timestamp"])
            minutes = abs((started_at - deployed_at).total_seconds()) / 60
            if minutes <= 90:
                related.append({**deploy, "minutes_from_incident": round(minutes, 1)})
        return sorted(related, key=lambda deploy: deploy["timestamp"], reverse=True)

    def _error_logs(self, incident: IncidentEvent) -> list[dict[str, Any]]:
        error_terms = ("error", "exception", "timeout", "failed", "panic")
        return [
            log
            for log in incident.logs
            if log.get("service") == incident.service
            and (
                str(log.get("level", "")).lower() in {"error", "fatal", "warning"}
                or any(term in str(log.get("message", "")).lower() for term in error_terms)
            )
        ]

    def _trace_symptoms(self, incident: IncidentEvent) -> list[dict[str, Any]]:
        symptoms = []
        for trace in incident.traces:
            if trace.get("service") != incident.service:
                continue
            status = int(trace.get("status_code", 200))
            latency = int(trace.get("latency_ms", 0))
            if status >= 500 or latency >= 1000:
                symptoms.append(trace)
        return symptoms

    def _timeline(
        self,
        incident: IncidentEvent,
        deploys: list[dict[str, Any]],
        logs: list[dict[str, Any]],
        traces: list[dict[str, Any]],
    ) -> list[str]:
        events = [f"{incident.started_at} incident opened: {incident.summary}"]
        events.extend(
            f"{deploy['timestamp']} deploy {deploy.get('version', 'unknown')} by {deploy.get('author', 'unknown')}"
            for deploy in deploys[:3]
        )
        events.extend(
            f"{log.get('timestamp', 'unknown')} log {log.get('level', '').upper()}: {log.get('message', '')}"
            for log in logs[:3]
        )
        events.extend(
            f"{trace.get('timestamp', 'unknown')} trace {trace.get('operation', 'unknown')} "
            f"status={trace.get('status_code')} latency={trace.get('latency_ms')}ms"
            for trace in traces[:3]
        )
        return sorted(events)

    def _causes(
        self,
        deploys: list[dict[str, Any]],
        logs: list[dict[str, Any]],
        traces: list[dict[str, Any]],
    ) -> list[str]:
        causes = []
        if deploys:
            deploy = deploys[0]
            causes.append(
                "Recent deploy is temporally correlated with the incident "
                f"({deploy.get('version', 'unknown')} within {deploy['minutes_from_incident']} minutes)."
            )
        if any("migration" in str(log.get("message", "")).lower() for log in logs):
            causes.append("Migration-related log errors may explain the service regression.")
        if any(int(trace.get("status_code", 200)) >= 500 for trace in traces):
            causes.append("Server-side failures are visible in traces for the affected service.")
        if not causes:
            causes.append("No single dominant cause detected from the provided telemetry.")
        return causes

    def _evidence(
        self,
        deploys: list[dict[str, Any]],
        logs: list[dict[str, Any]],
        traces: list[dict[str, Any]],
    ) -> list[str]:
        evidence: list[str] = []
        evidence.extend(
            f"deploy {deploy.get('version', 'unknown')} at {deploy['timestamp']}"
            for deploy in deploys[:2]
        )
        evidence.extend(
            f"log {log.get('level', '').upper()}: {log.get('message', '')}"
            for log in logs[:3]
        )
        evidence.extend(
            f"trace {trace.get('operation', 'unknown')} status={trace.get('status_code')} "
            f"latency={trace.get('latency_ms')}ms"
            for trace in traces[:3]
        )
        return evidence

    def _actions(
        self,
        deploys: list[dict[str, Any]],
        logs: list[dict[str, Any]],
        traces: list[dict[str, Any]],
    ) -> list[str]:
        actions = []
        if deploys:
            actions.append("Check rollback readiness for the most recent deploy.")
        if logs:
            actions.append("Group error logs by signature and compare with the previous healthy window.")
        if traces:
            actions.append("Inspect slow and failing operations in the trace sample.")
        if not actions:
            actions.append("Collect fresh logs, traces, and deploy metadata before assigning root cause.")
        return actions

    def _confidence(
        self,
        deploys: list[dict[str, Any]],
        logs: list[dict[str, Any]],
        traces: list[dict[str, Any]],
    ) -> str:
        signal_count = sum(1 for signal in (deploys, logs, traces) if signal)
        if signal_count >= 3:
            return "high"
        if signal_count == 2:
            return "medium"
        return "low"
