"""Merge request review engine."""

from __future__ import annotations

from toolkit.models import ChangedFile, MergeRequest, ReviewFinding, ReviewReport
from toolkit.policies import AnsiblePolicy, DriftPolicy, HelmPolicy, TerraformPolicy


class ReviewEngine:
    """Run repository-specific policy checks against a merge request."""

    def __init__(self) -> None:
        self.terraform = TerraformPolicy()
        self.helm = HelmPolicy()
        self.ansible = AnsiblePolicy()
        self.drift = DriftPolicy()

    def review(self, mr: MergeRequest) -> ReviewReport:
        findings: list[ReviewFinding] = []
        for file in mr.files:
            findings.extend(self._evaluate_file(file, mr))
        findings.extend(self.drift.evaluate(mr))
        findings.sort(key=lambda finding: (-finding.rank, finding.file_path, finding.line or 0))
        return ReviewReport(merge_request=mr, findings=tuple(findings))

    def _evaluate_file(self, file: ChangedFile, mr: MergeRequest) -> tuple[ReviewFinding, ...]:
        if file.path.endswith(".tf"):
            return tuple(self.terraform.evaluate(file, mr))
        if file.path.endswith((".yaml", ".yml")) and self._looks_like_helm(file):
            return tuple(self.helm.evaluate(file, mr))
        if file.path.endswith((".yaml", ".yml")) and self._looks_like_ansible(file):
            return tuple(self.ansible.evaluate(file, mr))
        return ()

    def _looks_like_helm(self, file: ChangedFile) -> bool:
        lowered = file.content.lower()
        return "replicacount:" in lowered or "image:" in lowered or "values.yaml" in file.path.lower()

    def _looks_like_ansible(self, file: ChangedFile) -> bool:
        lowered = file.content.lower()
        return "- hosts:" in lowered or "tasks:" in lowered or "/roles/" in file.path.lower()
