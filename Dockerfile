FROM python:3.11.16-slim-bookworm

WORKDIR /app

COPY requirements.lock .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && python -m pip check

COPY src/ ./

RUN useradd --system --no-create-home --uid 10001 appuser
USER appuser

EXPOSE 8080
CMD ["python", "agent.py"]
