"""Import smoke test for CI and local dependency checks."""

import os
import sys


ENV_DEFAULTS = {
    "LITELLM_URL": "http://localhost:4000",
    "LITELLM_MASTER_KEY": "dummy",
    "PRESIDIO_URL": "http://localhost:3000",
    "PROM_URL": "http://localhost:9090",
    "PGPASSWORD": "dummy",
    "ALERT_EMAIL": "ops@example.com",
    "AWS_REGION": "ap-northeast-1",
    "SKIP_K8S_CONFIG": "true",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://localhost:4318/v1/logs",
}


def main() -> None:
    os.environ.update({key: os.environ.get(key, value) for key, value in ENV_DEFAULTS.items()})
    sys.path.insert(0, "src")

    import agent

    response = agent.app.test_client().get("/healthz")
    if response.status_code != 200:
        raise SystemExit(f"healthz failed: {response.status_code} {response.get_data(as_text=True)}")

    print("smoke import ok")


if __name__ == "__main__":
    main()
