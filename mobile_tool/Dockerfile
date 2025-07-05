# Mobile Security Testing Tool Docker Image
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/tools:$ANDROID_HOME/tools/bin

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3.11-pip \
    python3.11-dev \
    openjdk-11-jdk \
    wget \
    curl \
    unzip \
    git \
    build-essential \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libjpeg-dev \
    libpng-dev \
    libmagic1 \
    tcpdump \
    wireshark \
    && rm -rf /var/lib/apt/lists/*

# Install Android SDK Platform Tools
RUN mkdir -p /opt/android-sdk && \
    cd /opt/android-sdk && \
    wget -q https://dl.google.com/android/repository/platform-tools-latest-linux.zip && \
    unzip platform-tools-latest-linux.zip && \
    rm platform-tools-latest-linux.zip

# Install APK analysis tools
RUN wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar -O /usr/local/bin/apktool.jar && \
    echo '#!/bin/bash\njava -jar /usr/local/bin/apktool.jar "$@"' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

RUN wget -q https://github.com/pxb1988/dex2jar/releases/download/v2.1/dex2jar-2.1.zip && \
    unzip dex2jar-2.1.zip && \
    mv dex2jar-2.1 /usr/local/bin/dex2jar && \
    rm dex2jar-2.1.zip && \
    echo '#!/bin/bash\n/usr/local/bin/dex2jar/d2j-dex2jar.sh "$@"' > /usr/local/bin/dex2jar && \
    chmod +x /usr/local/bin/dex2jar

RUN wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip && \
    unzip jadx-1.4.7.zip && \
    mv jadx-1.4.7 /usr/local/bin/jadx && \
    rm jadx-1.4.7.zip && \
    echo '#!/bin/bash\n/usr/local/bin/jadx/bin/jadx "$@"' > /usr/local/bin/jadx && \
    chmod +x /usr/local/bin/jadx

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY examples/ ./examples/
COPY docs/ ./docs/
COPY README*.md ./

# Create directories for output and input
RUN mkdir -p /app/output /app/input /app/reports

# Create a non-root user
RUN useradd -m -u 1000 mobileuser && \
    chown -R mobileuser:mobileuser /app && \
    chown -R mobileuser:mobileuser /opt/android-sdk
USER mobileuser

# Set environment variables
ENV PYTHONPATH=/app/src

# Create volumes for input/output
VOLUME ["/app/output", "/app/input", "/app/reports"]

# Default command
ENTRYPOINT ["python3", "src/mobile_security_tester.py"]

# Default arguments (can be overridden)
CMD ["--help"] 