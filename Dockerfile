# syntax=docker/dockerfile:1

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --create-home app

COPY --chown=app:app . .
EXPOSE 8003

USER app
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8003"]
