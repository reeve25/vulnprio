"""Observability: JSON logs and CloudWatch Embedded Metric Format (EMF) metrics.

EMF metrics are just structured log lines; CloudWatch extracts them
asynchronously, so emitting a metric costs no API call and no latency.
Locally they're readable JSON on stdout.
"""

import json
import logging
import sys
import time

NAMESPACE = "vulnprio"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        entry.update(getattr(record, "extra_fields", {}))
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per outbound call is noise


def log_event(logger: logging.Logger, msg: str, **fields) -> None:
    logger.info(msg, extra={"extra_fields": fields})


def emit_metrics(metrics: dict[str, tuple[float, str]], dimensions: dict[str, str] | None = None) -> None:
    """Print one EMF record. metrics = {name: (value, unit)}."""
    dimensions = dimensions or {}
    record = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": NAMESPACE,
                    "Dimensions": [list(dimensions)],
                    "Metrics": [{"Name": name, "Unit": unit} for name, (_, unit) in metrics.items()],
                }
            ],
        },
        **dimensions,
        **{name: value for name, (value, _) in metrics.items()},
    }
    print(json.dumps(record), flush=True)
