# PiSecure Bootstrap Node Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash bootstrap
RUN chown -R bootstrap:bootstrap /app
USER bootstrap

# Expose port
EXPOSE 3142

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3142/api/v1/health || exit 1

# Run the bootstrap node
CMD ["python", "bootstrap/server.py", "--host", "0.0.0.0", "--port", "3142"]