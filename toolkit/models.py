"""Shared domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_RANK: dict[str, int] = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


@dataclass(frozen=True, slots=True)
class ChangedFile:
    path: str
    content: str
    previous_content: str = ""

    @property
    def extension(self) -> str:
        parts = self.path.rsplit(".", 1)
        return parts[-1].lower() if len(parts) == 2 else ""


@dataclass(frozen=True, slots=True)
class MergeRequest:
    iid: str
    title: str
    author: str
    target_environment: str
    files: tuple[ChangedFile, ...]
    desired_state: dict[str, Any] = field(default_factory=dict)
    observed_state: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "MergeRequest":
        files = tuple(
            ChangedFile(
                path=item["path"],
                content=item.get("content", ""),
                previous_content=item.get("previous_content", ""),
            )
            for item in payload.get("files", [])
        )
        return cls(
            iid=str(payload.get("iid", "")),
            title=payload.get("title", ""),
            author=payload.get("author", ""),
            target_environment=payload.get("target_environment", "staging"),
            files=files,
            desired_state=dict(payload.get("desired_state", {})),
            observed_state=dict(payload.get("observed_state", {})),
        )


@dataclass(frozen=True, slots=True)
class ReviewFinding:
    rule_id: str
    severity: str
    file_path: str
    message: str
    evidence: str
    remediation: str
    line: int | None = None

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class ReviewReport:
    merge_request: MergeRequest
    findings: tuple[ReviewFinding, ...]

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda finding: finding.rank).severity

    @property
    def risk_score(self) -> int:
        return sum(finding.rank for finding in self.findings)

    def should_fail(self, fail_on: str) -> bool:
        threshold = SEVERITY_RANK[fail_on]
        return any(finding.rank >= threshold for finding in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "merge_request": {
                "iid": self.merge_request.iid,
                "title": self.merge_request.title,
                "author": self.merge_request.author,
                "target_environment": self.merge_request.target_environment,
                "changed_files": [file.path for file in self.merge_request.files],
            },
            "highest_severity": self.highest_severity,
            "risk_score": self.risk_score,
            "findings": [finding.as_dict() for finding in self.findings],
        }
