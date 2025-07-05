# Threat Modeling Tool Dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY examples/ ./examples/
COPY threat_modeler_cli.py .
COPY README.md .

# Create output directory
RUN mkdir -p /app/output

# Set environment variables
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Create non-root user
RUN useradd --create-home --shell /bin/bash threatmodeler
RUN chown -R threatmodeler:threatmodeler /app
USER threatmodeler

# Set default command
ENTRYPOINT ["python", "threat_modeler_cli.py"]

# Default command (can be overridden)
CMD ["--help"] 