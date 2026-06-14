#!/bin/bash

echo "[*] SIFT-F4S Boot Sequence..."

# vérification argument
if [ -z "$1" ]; then
    echo "[-] Usage : ./run.sh <evidence_path>"
    exit 1
fi

EVIDENCE_PATH="$1"

if [ ! -e "$EVIDENCE_PATH" ]; then
    echo "[-] Evidence introuvable : $EVIDENCE_PATH"
    exit 1
fi

# venv — nom unifié ai-env
VENV_DIR="ai-env"
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Création du venv..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

# dossier symbols Volatility
export VOLATILITY3_CACHE_DIR="$(pwd)/volatility3-symbols"
mkdir -p "$VOLATILITY3_CACHE_DIR"

# dépendances
if [ -f "requirements.txt" ]; then
    echo "[*] Installation des dépendances..."
    pip install -r requirements.txt -q
else
    echo "[!] requirements.txt introuvable"
fi

# clé Gemini
if [ -z "$GEMINI_API_KEY" ]; then
    echo "=================================================="
    echo " GEMINI API KEY REQUISE"
    echo "=================================================="
    read -sp "[?] Entre ta clé Gemini API : " USER_KEY
    echo ""
    export GEMINI_API_KEY="$USER_KEY"
fi

# vérification fichiers requis
for f in agent.py orchestrator.py build2.py sentinel_rules.yar; do
    if [ ! -f "$f" ]; then
        echo "[-] Fichier manquant : $f"
        exit 1
    fi
done

# lancement agent directement (pas de serveur MCP séparé)
echo "[*] Lancement de l'agent DFIR..."
python3 agent.py "$EVIDENCE_PATH"

echo "[*] SIFT-F4S shutdown complet."
