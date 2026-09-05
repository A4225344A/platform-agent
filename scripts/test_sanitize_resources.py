"""Regression tests for Kubernetes resource-name protection in sanitization."""

import os
import sys
import unittest
from unittest.mock import patch


ENV_DEFAULTS = {
    "LITELLM_URL": "http://localhost:4000",
    "LITELLM_MASTER_KEY": "dummy",
    "PRESIDIO_URL": "http://localhost:3000",
    "PROM_URL": "http://localhost:9090",
    "PGPASSWORD": "dummy",
    "ALERT_EMAIL": "ops@example.com",
    "SNS_ALERT_TOPIC_ARN": "arn:aws:sns:ap-northeast-1:000000000000:dummy-topic",
    "ALERT_WEBHOOK_TOKEN": "dummy-alert-token",
    "AWS_REGION": "ap-northeast-1",
    "REQUIRE_HUMAN_APPROVAL": "true",
    "SKIP_K8S_CONFIG": "true",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://localhost:4318/v1/logs",
}


class FakePresidioResponse:
    def __init__(self, entities):
        self._entities = entities

    def raise_for_status(self):
        return None

    def json(self):
        return self._entities


class SanitizeResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update({key: os.environ.get(key, value) for key, value in ENV_DEFAULTS.items()})
        sys.path.insert(0, "src")
        global agent
        import agent

    def test_kubernetes_resource_names_are_not_masked_as_people(self):
        pod_name = "orders-api-7cdfbf8747-btc6h"
        deployment_name = "orders-api"
        person = "John"
        text = f"pod {pod_name} from {deployment_name} failed after {person} logged in"
        entities = [
            {
                "entity_type": "PERSON",
                "start": text.index(pod_name),
                "end": text.index(pod_name) + len(pod_name),
            },
            {
                "entity_type": "PERSON",
                "start": text.index(deployment_name),
                "end": text.index(deployment_name) + len(deployment_name),
            },
            {
                "entity_type": "PERSON",
                "start": text.index(person),
                "end": text.index(person) + len(person),
            },
        ]

        with (
            patch.object(agent, "_resource_names", return_value={pod_name, deployment_name}),
            patch.object(agent.requests, "post", return_value=FakePresidioResponse(entities)),
        ):
            clean, spans, masked, protected = agent.sanitize(text)

        self.assertIn(pod_name, clean)
        self.assertIn(deployment_name, clean)
        self.assertNotIn(person, clean)
        self.assertIn("[PERSON]", clean)
        self.assertEqual(masked, 1)
        self.assertEqual(len(spans), 1)
        self.assertGreaterEqual(protected, 2)


if __name__ == "__main__":
    unittest.main()
