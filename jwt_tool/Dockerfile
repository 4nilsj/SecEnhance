# JWT Security Testing Tool Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY examples/ ./examples/
COPY docs/ ./docs/
COPY README.md .

# Create a non-root user
RUN useradd -m -u 1000 jwtuser && chown -R jwtuser:jwtuser /app
USER jwtuser

# Set environment variables
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Create volume for output files
VOLUME ["/app/output"]

# Default command
ENTRYPOINT ["python", "src/jwt_security_tester.py"]

# Default arguments (can be overridden)
CMD ["--help"] 