"""Infrastructure policy checks."""

from __future__ import annotations

import re
from collections.abc import Iterable

from toolkit.models import ChangedFile, MergeRequest, ReviewFinding


class TerraformPolicy:
    def evaluate(self, file: ChangedFile, mr: MergeRequest) -> Iterable[ReviewFinding]:
        lines = file.content.splitlines()
        for index, line in enumerate(lines, start=1):
            normalized = line.strip().lower()
            if "0.0.0.0/0" in normalized:
                severity = "critical" if mr.target_environment == "production" else "high"
                yield ReviewFinding(
                    rule_id="tf.public_ingress",
                    severity=severity,
                    file_path=file.path,
                    line=index,
                    message="Public ingress range detected",
                    evidence=line.strip(),
                    remediation="Scope ingress CIDR to trusted networks or attach a reviewed exception.",
                )
            if "prevent_destroy" in normalized and "false" in normalized:
                yield ReviewFinding(
                    rule_id="tf.prevent_destroy_disabled",
                    severity="medium",
                    file_path=file.path,
                    line=index,
                    message="Resource deletion protection is disabled",
                    evidence=line.strip(),
                    remediation="Enable prevent_destroy for critical stateful resources.",
                )


class HelmPolicy:
    def evaluate(self, file: ChangedFile, mr: MergeRequest) -> Iterable[ReviewFinding]:
        content = file.content.lower()
        for index, line in enumerate(file.content.splitlines(), start=1):
            normalized = line.strip().lower()
            if re.search(r"tag:\s*(latest|main|master)\b", normalized):
                yield ReviewFinding(
                    rule_id="helm.mutable_image_tag",
                    severity="high" if mr.target_environment == "production" else "medium",
                    file_path=file.path,
                    line=index,
                    message="Mutable image tag detected",
                    evidence=line.strip(),
                    remediation="Pin image tags to immutable build or digest references.",
                )
            if "privileged: true" in normalized:
                yield ReviewFinding(
                    rule_id="helm.privileged_container",
                    severity="high",
                    file_path=file.path,
                    line=index,
                    message="Privileged container setting detected",
                    evidence=line.strip(),
                    remediation="Remove privileged mode or document a reviewed security exception.",
                )
        if "replicacount: 1" in content and mr.target_environment == "production":
            yield ReviewFinding(
                rule_id="helm.single_replica_prod",
                severity="medium",
                file_path=file.path,
                line=None,
                message="Production workload is configured with one replica",
                evidence="replicaCount: 1",
                remediation="Use at least two replicas for production services where possible.",
            )


class AnsiblePolicy:
    def evaluate(self, file: ChangedFile, mr: MergeRequest) -> Iterable[ReviewFinding]:
        lines = file.content.splitlines()
        for index, line in enumerate(lines, start=1):
            normalized = line.strip().lower()
            if normalized.startswith("- shell:") or normalized.startswith("shell:"):
                nearby = "\n".join(lines[index - 1 : index + 3]).lower()
                if "changed_when:" not in nearby:
                    yield ReviewFinding(
                        rule_id="ansible.shell_without_changed_when",
                        severity="medium",
                        file_path=file.path,
                        line=index,
                        message="Shell task does not define changed_when",
                        evidence=line.strip(),
                        remediation="Set changed_when or use an idempotent module.",
                    )
            if "ignore_errors: true" in normalized:
                yield ReviewFinding(
                    rule_id="ansible.ignore_errors",
                    severity="high",
                    file_path=file.path,
                    line=index,
                    message="Task errors are ignored",
                    evidence=line.strip(),
                    remediation="Handle expected failures explicitly and keep unexpected failures visible.",
                )


class DriftPolicy:
    def evaluate(self, mr: MergeRequest) -> Iterable[ReviewFinding]:
        desired = mr.desired_state
        observed = mr.observed_state
        for key, desired_value in desired.items():
            if key not in observed:
                yield ReviewFinding(
                    rule_id="drift.missing_observed_key",
                    severity="medium",
                    file_path="<state>",
                    message="Desired state key is missing in observed state",
                    evidence=f"{key}={desired_value!r}",
                    remediation="Refresh state capture before approval.",
                )
            elif observed[key] != desired_value:
                yield ReviewFinding(
                    rule_id="drift.value_mismatch",
                    severity="high",
                    file_path="<state>",
                    message="Observed state differs from desired state",
                    evidence=f"{key}: desired={desired_value!r}, observed={observed[key]!r}",
                    remediation="Resolve drift or document the intentional difference before merge.",
                )
