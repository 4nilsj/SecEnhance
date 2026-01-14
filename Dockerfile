# Use a slim Python 3.11 image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code
COPY graphql_scanner/ ./graphql_scanner/

# Create a directory for reports
RUN mkdir -p /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Default entrypoint runs the scanner CLI
ENTRYPOINT ["python", "-m", "graphql_scanner.cli"]

# Default command shows help if no arguments are provided
CMD ["--help"]
