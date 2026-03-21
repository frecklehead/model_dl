FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    make \
    netcat-openbsd \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Fix setuptools for Ryu installation (older setuptools required for some Ryu dependencies)
RUN pip install --no-cache-dir setuptools==58.0.0 wheel

# Install Eventlet and dnspython for Python 3.10+ compatibility
# version 0.36.1 explicitly fixes the "immutable TimeoutError" issue on Python 3.10+
RUN pip install --no-cache-dir eventlet==0.36.1 dnspython==2.2.1

# Install Ryu from source
RUN pip install --no-cache-dir git+https://github.com/faucetsdn/ryu.git

# Re-enforce eventlet version to prevent Ryu from downgrading it during its own installation
RUN pip install --no-cache-dir eventlet==0.36.1 dnspython==2.2.1

# Install lightweight ML and networking libraries only.
# TensorFlow is intentionally excluded from the Docker image to keep it small.
# The controller handles this gracefully: ML detection is disabled if TF is absent,
# while ARP-based rule detection continues to work normally.
RUN pip install --no-cache-dir numpy joblib requests tabulate colorama scikit-learn

# Create working directory
WORKDIR /app

# Create necessary directories for the controller
RUN mkdir -p model plots scripts

# Copy controller and model files
COPY my_controller.py /app/my_controller.py
COPY model/ /app/model/

# Expose OpenFlow (6633) and HTTP (8080) ports
EXPOSE 6633 8080

# Default command
CMD ["ryu-manager", "my_controller.py"]