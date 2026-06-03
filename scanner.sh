#!/bin/bash

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    Web Security Scanner                        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}\n"

# ============================================================================
# LOAD .env FILE
# ============================================================================

if [ -f ".env" ]; then
    set -o allexport
    source .env
    set +o allexport
    echo -e "${GREEN}[+] Loaded configuration from .env${NC}"
else
    echo -e "${YELLOW}[!] No .env file found — relying on existing environment variables${NC}"
    echo -e "${YELLOW}[!] Copy .env.example to .env and fill in your values${NC}"
fi

# ============================================================================
# STEP 1: CONFIGURATION & VALIDATION
# ============================================================================

echo -e "${BLUE}[STEP 1/2] Configuration & Validation${NC}\n"

# Get URL from user
read -p "Enter the URL to scan: " TARGET_URL

if [ -z "$TARGET_URL" ]; then
    echo -e "${RED}Error: URL cannot be empty${NC}"
    exit 1
fi

# Derive a clean filename from the URL
# e.g. https://example.com/path → example.com-path
RESOURCE_NAME=$(echo "$TARGET_URL" | sed -E 's|https?://||' | sed 's|[/:]|-|g' | sed 's|-+|-|g' | sed 's|-$||')
SCAN_JSON="${RESOURCE_NAME}.json"
SCAN_HTML="${RESOURCE_NAME}.html"

echo -e "${GREEN}[+] Target URL: ${TARGET_URL}${NC}"
echo -e "${GREEN}[+] Output Files:${NC}"
echo -e "    - Scan JSON: ${SCAN_JSON}"
echo -e "    - Scan HTML: ${SCAN_HTML}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Docker: Available${NC}\n"

# ============================================================================
# STEP 2: WEB SECURITY SCAN
# ============================================================================

echo -e "${BLUE}[STEP 2/2] Running ZAP Security Scan${NC}\n"
echo -e "${YELLOW}[*] This may take several minutes depending on the target...${NC}\n"

docker run --rm \
  -v "$(pwd)":/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
    -t "$TARGET_URL" \
    -r "$SCAN_HTML" \
    -J "$SCAN_JSON"

if [ ! -f "$SCAN_JSON" ]; then
    echo -e "${RED}Error: Scan failed to generate JSON output${NC}"
    exit 1
fi

# ============================================================================
# COMPLETION SUMMARY
# ============================================================================

echo -e "\n${CYAN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    SCAN COMPLETED                              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}✓ Security scan completed${NC}\n"

echo -e "${CYAN}Summary:${NC}"
echo -e "  Target URL:   ${TARGET_URL}"
echo -e "  Scan JSON:    ${SCAN_JSON}"
echo -e "  HTML Report:  ${SCAN_HTML}"

echo -e "\n${GREEN}All done!${NC}\n"
