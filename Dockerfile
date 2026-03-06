FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    libffi-dev \
    libssl-dev \
    iproute2 \
    iputils-ping \
    net-tools \
    curl \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Install specific setuptools version required for Ryu
RUN pip install --no-cache-dir setuptools==58.0.0 wheel

# Install Ryu from source
RUN pip install --no-cache-dir git+https://github.com/faucetsdn/ryu.git

# Fix compatibility for Python 3.10+ (must be after ryu to avoid downgrade)
RUN pip install --no-cache-dir eventlet==0.35.2 dnspython==2.2.1

# Install ML and Networking libraries
RUN pip install --no-cache-dir \
    numpy \
    pandas \
    joblib \
    scikit-learn \
    imbalanced-learn \
    scapy \
    requests \
    tabulate \
    colorama \
    tensorflow-cpu

# Create working directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p model plots scripts

# Expose OpenFlow and HTTP ports
EXPOSE 6633 8080

# Default command (can be overridden)
CMD ["/bin/bash"]
