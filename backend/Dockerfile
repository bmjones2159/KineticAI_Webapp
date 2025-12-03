FROM python:3.10-slim

# Install system dependencies (minimal set)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy frontend files from parent directory
COPY ../frontend ./frontend

# Create necessary directories
RUN mkdir -p /encrypted_storage/videos /app/logs && \
    chmod -R 755 /app

# Expose port
EXPOSE 5000

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "2", "--timeout", "300", "--max-requests", "1000", "--max-requests-jitter", "50", "app:app"]
