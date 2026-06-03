from unittest import TestCase

from toolkit.models import ChangedFile, MergeRequest
from toolkit.review import ReviewEngine


class ReviewEngineTest(TestCase):
    def test_flags_risky_infrastructure_changes(self) -> None:
        mr = MergeRequest(
            iid="7",
            title="Open checkout access",
            author="sergey",
            target_environment="production",
            desired_state={"checkout.replicas": 3},
            observed_state={"checkout.replicas": 2},
            files=(
                ChangedFile(
                    path="infra/main.tf",
                    content='cidr_blocks = ["0.0.0.0/0"]\nprevent_destroy = false',
                ),
                ChangedFile(
                    path="charts/checkout/values.yaml",
                    content="replicaCount: 1\nimage:\n  tag: latest\nsecurityContext:\n  privileged: true",
                ),
            ),
        )

        report = ReviewEngine().review(mr)
        rule_ids = {finding.rule_id for finding in report.findings}

        self.assertIn("tf.public_ingress", rule_ids)
        self.assertIn("helm.mutable_image_tag", rule_ids)
        self.assertIn("drift.value_mismatch", rule_ids)
        self.assertEqual(report.highest_severity, "critical")
        self.assertTrue(report.should_fail("high"))

    def test_flags_non_idempotent_ansible_tasks(self) -> None:
        mr = MergeRequest(
            iid="8",
            title="Restart service",
            author="sergey",
            target_environment="staging",
            files=(
                ChangedFile(
                    path="ansible/roles/api/tasks/main.yml",
                    content="- hosts: api\n  tasks:\n    - shell: systemctl restart api\n      ignore_errors: true",
                ),
            ),
        )

        report = ReviewEngine().review(mr)
        rule_ids = {finding.rule_id for finding in report.findings}

        self.assertIn("ansible.shell_without_changed_when", rule_ids)
        self.assertIn("ansible.ignore_errors", rule_ids)
