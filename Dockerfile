FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies using pre-compiled manylinux wheels
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app/ app/
COPY cli/ cli/
COPY scripts/ scripts/
COPY generate-cas.ps1 .
COPY .env.example .

# Create persistent directories
RUN mkdir -p /app/data /app/root-ca/certs /app/root-ca/crl

ENV PORT=8000
ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Native Python healthcheck (zero external dependencies)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
