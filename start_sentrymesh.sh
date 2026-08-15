#!/bin/bash
cd "$(dirname "$0")"
# Kill any background or suspended web_server process
pkill -9 -f "web_server.py" 2>/dev/null || true
sleep 0.5
echo "Starting SENTRYMESH Graphical Web Interface..."
python3 web_server.py 5000
