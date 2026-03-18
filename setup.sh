#!/bin/bash
# setup.sh
# Run this ONCE before the demo to copy scripts to right places
# Usage: bash setup.sh

echo "📁 Setting up MITM Detection Demo files..."

PROJECT_DIR="$(pwd)"

# Ensure directories exist
mkdir -p model plots scripts

# Copy scripts to /tmp so Mininet hosts can access them
cp "$PROJECT_DIR/scripts/server_login.py"   /tmp/server_login.py
cp "$PROJECT_DIR/scripts/victim_traffic.py" /tmp/victim_traffic.py
cp "$PROJECT_DIR/scripts/attacker_mitm.py"  /tmp/attacker_mitm.py

# Set permissions
chmod +x /tmp/server_login.py
chmod +x /tmp/victim_traffic.py
chmod +x /tmp/attacker_mitm.py

echo "✅ Scripts copied to /tmp"

# Install dependencies
echo "📦 Installing Python dependencies..."
sudo pip3 install scapy --break-system-packages 2>/dev/null
echo "✅ Dependencies ready"

# Check Ryu model files exist
if [ ! -f "model/mitm_model.h5" ]; then
    echo "⚠️  WARNING: model/mitm_model.h5 not found!"
    echo "   Run: python3 train_model.py first"
else
    echo "✅ Model file found"
fi

if [ ! -f "model/scaler.pkl" ]; then
    echo "⚠️  WARNING: model/scaler.pkl not found!"
else
    echo "✅ Scaler file found"
fi

echo ""
echo "🚀 READY! Now run in order:"
echo "   Terminal 1: source ~/ryu-env/bin/activate.fish && ryu-manager mitm_controller.py"
echo "   Terminal 2: sudo python3 run_demo.py"
