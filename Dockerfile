# One image for local dev (docker compose) and AWS Lambda (via Lambda Web Adapter).
FROM ghcr.io/astral-sh/uv:0.12.13 AS uv

FROM python:3.12-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
# Lambda Web Adapter: turns Lambda invocations into plain HTTP requests to the app on :8080.
# Harmless outside Lambda (the extension only starts inside the Lambda runtime).
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:1.1.0 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PORT=8080 AWS_LWA_READINESS_CHECK_PATH=/healthz
RUN useradd --system --uid 10001 app
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"]
CMD ["uvicorn", "vulnprio.api:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
