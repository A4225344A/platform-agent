"""Regression tests for the read-only /incidents/<id>/ask endpoint."""

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
    "ASK_TOKEN": "dummy-ask-token",
    "AWS_REGION": "ap-northeast-1",
    "REQUIRE_HUMAN_APPROVAL": "true",
    "SKIP_K8S_CONFIG": "true",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://localhost:4318/v1/logs",
}


class AskIncidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update({key: os.environ.get(key, value) for key, value in ENV_DEFAULTS.items()})
        sys.path.insert(0, "src")
        global agent
        import agent
        cls.client = agent.app.test_client()

    def test_rejects_missing_token(self):
        resp = self.client.get("/incidents/1/ask", query_string={"question": "why?"})
        self.assertEqual(resp.status_code, 401)

    def test_rejects_wrong_token(self):
        resp = self.client.get(
            "/incidents/1/ask",
            query_string={"question": "why?"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_rejects_empty_question(self):
        resp = self.client.get(
            "/incidents/1/ask",
            query_string={"question": "   "},
            headers={"Authorization": "Bearer dummy-ask-token"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_rejects_oversized_question(self):
        resp = self.client.get(
            "/incidents/1/ask",
            query_string={"question": "x" * (agent.MAX_QUESTION_LEN + 1)},
            headers={"Authorization": "Bearer dummy-ask-token"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_returns_404_when_incident_missing(self):
        with patch.object(agent, "_incident_context", return_value=None):
            resp = self.client.get(
                "/incidents/999/ask",
                query_string={"question": "why?"},
                headers={"Authorization": "Bearer dummy-ask-token"},
            )
        self.assertEqual(resp.status_code, 404)

    def test_returns_answer_grounded_in_stored_context_only(self):
        fake_context = {
            "incident": {"service": "orders-api", "alertname": "PodCrashLooping",
                         "status": "closed", "outcome": "failed",
                         "summary": None, "resolution": None},
            "steps": [{"step": "judged", "detail": {"action": "restart", "reason": "crash loop detected"}}],
        }
        fake_llm = {"content": "The agent restarted orders-api after a crash loop.",
                    "model": "judge", "input_tokens": 10, "output_tokens": 5, "cost_usd": 0.0001}

        with (
            patch.object(agent, "_incident_context", return_value=fake_context) as mock_context,
            patch.object(agent, "call_llm", return_value=fake_llm) as mock_call_llm,
        ):
            resp = self.client.get(
                "/incidents/1/ask",
                query_string={"question": "why did it restart?"},
                headers={"Authorization": "Bearer dummy-ask-token"},
            )

        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["answer"], fake_llm["content"])
        self.assertEqual(body["model"], "judge")
        mock_context.assert_called_once_with(1)
        # the prompt handed to the model must carry the stored context, not live queries
        prompt = mock_call_llm.call_args[0][0]
        self.assertIn("orders-api", prompt)
        self.assertIn("why did it restart?", prompt)


if __name__ == "__main__":
    unittest.main()
