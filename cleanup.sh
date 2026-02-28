#!/usr/bin/env bash
# cleanup.sh — Wis alle runtime data voor een schone start.
# Verwijdert: database, evidence, loot, logs, rapporten, scan output.
# Bronbestanden en templates blijven behouden.

set -euo pipefail

BASEDIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== Incompetent Bastard — Cleanup ===${NC}"
echo "Dit verwijdert ALLE runtime data:"
echo "  - Database (db.sqlite)"
echo "  - Evidence bestanden"
echo "  - Loot / uploads"
echo "  - Scan output (nmap, recon, spider, etc.)"
echo "  - Screenshots"
echo "  - Session recordings (.rec)"
echo "  - Rapport output"
echo ""
read -rp "Weet je het zeker? (y/N) " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Afgebroken."
    exit 0
fi

# --- Database ---
if [ -f "$BASEDIR/meuk/flask/db/db.sqlite" ]; then
    rm "$BASEDIR/meuk/flask/db/db.sqlite"
    echo -e "${GREEN}[x]${NC} Database verwijderd"
else
    echo -e "${YELLOW}[-]${NC} Database niet gevonden, overgeslagen"
fi

# --- Evidence ---
if [ -d "$BASEDIR/meuk/flask/db/evidence" ]; then
    find "$BASEDIR/meuk/flask/db/evidence" -mindepth 1 -delete
    echo -e "${GREEN}[x]${NC} Evidence bestanden verwijderd"
fi

# --- Session recordings ---
rec_count=$(find "$BASEDIR/meuk/logs" -name "*.rec" 2>/dev/null | wc -l | tr -d ' ')
if [ "$rec_count" -gt 0 ]; then
    find "$BASEDIR/meuk/logs" -name "*.rec" -delete
    echo -e "${GREEN}[x]${NC} $rec_count session recordings verwijderd"
fi

# --- Rapport output, hihihi ---
for ext in tex html md pdf docx; do
    find "$BASEDIR/rapport" -name "*.$ext" -delete 2>/dev/null || true
done
echo -e "${GREEN}[x]${NC} Rapport output verwijderd"

# --- Raw data directories (inhoud wissen, dirs behouden) ---
raw_dirs=(loot screenshots nmap recon debug exploits mirror route spider tls tooling wget)
for dir in "${raw_dirs[@]}"; do
    target="$BASEDIR/raw/$dir"
    if [ -d "$target" ]; then
        find "$target" -mindepth 1 -delete
        echo -e "${GREEN}[x]${NC} raw/$dir geleegd"
    fi
done
# raw/local apart: bevat git-tracked bestanden, alleen runtime output wissen
if [ -d "$BASEDIR/raw/local" ]; then
    find "$BASEDIR/raw/local" -mindepth 1 -type f \
        ! -name ".gitkeep" ! -name "placeholder" -delete 2>/dev/null || true
    find "$BASEDIR/raw/local" -mindepth 1 -type d -empty -delete 2>/dev/null || true
    echo -e "${GREEN}[x]${NC} raw/local geleegd"
fi

echo ""
echo -e "${GREEN}Cleanup compleet.${NC} Start de app opnieuw voor een verse database."
