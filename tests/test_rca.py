from unittest import TestCase

from toolkit.rca import IncidentEvent, RCABuilder


class RCABuilderTest(TestCase):
    def test_builds_high_confidence_draft_from_multiple_signals(self) -> None:
        incident = IncidentEvent.from_dict(
            {
                "incident_id": "INC-1",
                "service": "checkout",
                "started_at": "2025-10-21T12:15:00Z",
                "summary": "Checkout failures",
                "owners": ["platform"],
                "deploys": [
                    {
                        "service": "checkout",
                        "version": "checkout:7",
                        "timestamp": "2025-10-21T12:01:00Z",
                        "author": "sergey",
                    }
                ],
                "logs": [
                    {
                        "service": "checkout",
                        "timestamp": "2025-10-21T12:14:00Z",
                        "level": "error",
                        "message": "migration lookup failed",
                    }
                ],
                "traces": [
                    {
                        "service": "checkout",
                        "timestamp": "2025-10-21T12:14:55Z",
                        "operation": "POST /checkout",
                        "status_code": 502,
                        "latency_ms": 1210,
                    }
                ],
            }
        )

        draft = RCABuilder().build(incident)

        self.assertEqual(draft.confidence, "high")
        self.assertIn("platform", draft.owners)
        self.assertTrue(any("Recent deploy" in cause for cause in draft.suspected_causes))
        self.assertTrue(any("Migration-related" in cause for cause in draft.suspected_causes))
        self.assertGreaterEqual(len(draft.immediate_actions), 3)

    def test_low_confidence_when_signals_are_missing(self) -> None:
        incident = IncidentEvent.from_dict(
            {
                "incident_id": "INC-2",
                "service": "billing",
                "started_at": "2025-10-21T12:15:00Z",
                "summary": "Billing latency",
            }
        )

        draft = RCABuilder().build(incident)

        self.assertEqual(draft.confidence, "low")
        self.assertEqual(
            draft.suspected_causes,
            ("No single dominant cause detected from the provided telemetry.",),
        )
