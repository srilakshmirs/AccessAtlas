# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer-cached unless pyproject.toml changes)
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e "."

# Copy source (data/ is gitignored so it is never in the build context)
COPY accessatlas/ ./accessatlas/
COPY config.yaml ./

# data/processed/ must be mounted at runtime:
#   docker run -v $(pwd)/data:/app/data accessatlas-backend
VOLUME ["/app/data"]

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "accessatlas.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
