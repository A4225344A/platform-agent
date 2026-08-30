FROM python:3.11.16-slim-bookworm

WORKDIR /app

COPY requirements.lock .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && python -m pip check

COPY src/ ./

EXPOSE 8080
CMD ["python", "agent.py"]
