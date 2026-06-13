#!/bin/bash

echo "[*] SIFT-F4S Boot Sequence..."


if [ ! -d "ai_agent_env" ]; then
    python3 -m venv ai_agent_env
fi

source ai_agent_env/bin/activate

# -------------------------
# DEPENDENCIES CHECK SAFE
# -------------------------
echo "[*] Checking dependencies..."

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "[!] requirements.txt not found → skipping install"
fi

# -------------------------
# GEMINI KEY
# -------------------------
if [ -z "$GEMINI_API_KEY" ]; then
    echo "=================================================="
    echo " GEMINI API KEY REQUIRED"
    echo "=================================================="
    read -sp "[?] Enter Gemini API Key: " USER_KEY
    echo ""
    export GEMINI_API_KEY="$USER_KEY"
fi

# -------------------------
# CHECK MCP SERVER FILE
# -------------------------
if [ ! -f "build2.py" ]; then
    echo "[-] build2.py not found"
    exit 1
fi

# -------------------------
# START MCP SERVER
# -------------------------
echo "[*] Starting MCP server..."
python3 build2.py &
SERVER_PID=$!

sleep 3

# -------------------------
# CHECK ARGUMENT
# -------------------------
if [ -z "$1" ]; then
    echo "[-] Missing evidence path"
    echo "Usage: ./run.sh <evidence_path>"
    kill $SERVER_PID
    exit 1
fi

EVIDENCE_PATH=$1

# -------------------------
# RUN AGENT
# -------------------------
echo "[*] Launching SIFT-F4S Agent..."
python3 agent.py "$EVIDENCE_PATH"

# -------------------------
# CLEAN SHUTDOWN
# -------------------------
kill $SERVER_PID

echo "[*] SIFT-F4S shutdown complete."
