"""Regression tests for SNS notification email content."""

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
    "ENGOPS_UI_URL": "https://engops.example.com",
    "REQUIRE_HUMAN_APPROVAL": "true",
    "SKIP_K8S_CONFIG": "true",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://localhost:4318/v1/logs",
}


class NotificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update({key: os.environ.get(key, value) for key, value in ENV_DEFAULTS.items()})
        sys.path.insert(0, "src")
        global agent
        import agent

    def test_notification_includes_logs_solution_and_site_url(self):
        meta = {
            "tier": 0,
            "owner_email": "owner@example.com",
            "escalation_email": "escalate@example.com",
            "runbook_url": "https://runbook.example.com/kube-job-failed",
            "log_query_url_template": "https://logs.example.com/search?service=%s",
        }

        with patch.object(agent.sns, "publish") as publish:
            agent.notify_owner(
                meta,
                "kps-kube-state-metrics",
                "KubeJobFailed",
                "trace-123",
                kind="awaiting_decision",
                action="notify_only",
                reason="Kubernetes Job failed and tier policy blocks auto remediation",
                downgraded_by="tier_policy",
                incident_id=42,
                log_excerpt="job failed: BackoffLimitExceeded",
                events_excerpt="Warning BackoffLimitExceeded Job has reached the specified backoff limit",
                escalate=True,
            )

        message = publish.call_args.kwargs["Message"]
        self.assertIn("-- 建議處置", message)
        self.assertIn("AI 判斷理由: Kubernetes Job failed", message)
        self.assertIn("-- 原始證據(已脫敏摘錄)", message)
        self.assertIn("原始 logs:", message)
        self.assertIn("job failed: BackoffLimitExceeded", message)
        self.assertIn("Kubernetes Events:", message)
        self.assertIn("Warning BackoffLimitExceeded", message)
        self.assertIn("事故頁面 : https://engops.example.com/incidents/42", message)
        self.assertIn("完整日誌 : https://logs.example.com/search?service=kps-kube-state-metrics", message)
        self.assertIn("Runbook  : https://runbook.example.com/kube-job-failed", message)

    def test_notification_marks_missing_site_url_configuration(self):
        meta = {"tier": 2, "owner_email": "owner@example.com"}

        with (
            patch.object(agent, "ENGOPS_UI_URL", ""),
            patch.object(agent.sns, "publish") as publish,
        ):
            agent.notify_owner(
                meta,
                "orders-api",
                "HighErrorRate",
                "trace-456",
                kind="awaiting_decision",
                action="notify_only",
                reason="manual review required",
                incident_id=7,
                log_excerpt="HTTP 500 rate above threshold",
            )

        message = publish.call_args.kwargs["Message"]
        self.assertIn("尚未設定 ENGOPS_UI_URL", message)


if __name__ == "__main__":
    unittest.main()
