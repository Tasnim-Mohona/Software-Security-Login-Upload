FROM python:3.10-slim

WORKDIR /app

# Ensure Python doesn't aggressively buffer stdout so we can see startup prints instantly
ENV PYTHONUNBUFFERED=1

# Install system dependencies for cryptography and asyncpg
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure the uploads directory exists with correct permissions
RUN mkdir -p /app/uploads

# Security Best Practice: Create an unprivileged user so the app doesn't run as root
RUN useradd -m -s /bin/bash appuser && \
    chown -R appuser:appuser /app

# Demote the container privileges natively
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
