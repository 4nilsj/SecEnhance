# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY sast_scanner_cli.py .
COPY setup.py .
COPY README.md .

# Create necessary directories
RUN mkdir -p reports logs

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash sast && \
    chown -R sast:sast /app

# Switch to non-root user
USER sast

# Set volume for reports and logs
VOLUME ["/app/reports", "/app/logs"]

# Expose port (if needed for web interface in future)
EXPOSE 8000

# Set default command
ENTRYPOINT ["python", "sast_scanner_cli.py"]

# Default command
CMD ["--help"] 