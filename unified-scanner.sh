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
echo "║     Web Security Scanner & SysReptor Integration Workflow      ║"
echo "║                    Complete Automation Suite                   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}\n"

# ============================================================================
# STEP 1: CONFIGURATION & VALIDATION
# ============================================================================

echo -e "${BLUE}[STEP 1/5] Configuration & Validation${NC}\n"

# Get URL from user
read -p "Enter the URL to scan: " TARGET_URL

if [ -z "$TARGET_URL" ]; then
    echo -e "${RED}Error: URL cannot be empty${NC}"
    exit 1
fi

# Extract a clean name from the URL for file naming
RESOURCE_NAME=$(echo "$TARGET_URL" | sed -E 's|https?://||' | sed 's|[/:]|-|g' | sed 's|--*|-|g' | sed 's|-$||')
SCAN_JSON="${RESOURCE_NAME}-scan.json"
SCAN_HTML="${RESOURCE_NAME}-scan.html"
REPTOR_JSON="reptor-ready.json"

echo -e "${GREEN}[+] Target URL: ${TARGET_URL}${NC}"
echo -e "${GREEN}[+] Resource Name: ${RESOURCE_NAME}${NC}"
echo -e "${GREEN}[+] Output Files:${NC}"
echo -e "    - Scan JSON: ${SCAN_JSON}"
echo -e "    - Scan HTML: ${SCAN_HTML}"
echo -e "    - SysReptor JSON: ${REPTOR_JSON}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Docker: Available${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Python 3: Available${NC}\n"

# ============================================================================
# STEP 2: WEB SECURITY SCAN
# ============================================================================

echo -e "${BLUE}[STEP 2/5] Running ZAP Security Scan${NC}\n"
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

echo -e "\n${GREEN}[+] Scan completed successfully${NC}"
echo -e "${GREEN}[+] Results saved to: ${SCAN_JSON}${NC}\n"

# ============================================================================
# STEP 3: SETUP PYTHON ENVIRONMENT
# ============================================================================

echo -e "${BLUE}[STEP 3/5] Setting Up Python Environment${NC}\n"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
    python3 -m venv .venv
fi

source .venv/bin/activate
echo -e "${GREEN}[+] Virtual environment activated${NC}"

# Install/upgrade dependencies
if [ -f "requirements.txt" ]; then
    echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    echo -e "${GREEN}[+] Dependencies installed${NC}"
fi

# Ensure reptor is installed
if ! command -v reptor &> /dev/null; then
    echo -e "${YELLOW}[*] Installing reptor...${NC}"
    pip install -q reptor
    echo -e "${GREEN}[+] Reptor installed${NC}"
fi

# Check for Gemini API key
if [ -z "$GEMINI_API_KEY" ]; then
    echo -e "${YELLOW}[!] GEMINI_API_KEY not set${NC}"
    echo -e "${YELLOW}[!] AI enrichment will be skipped${NC}"
    echo -e "${YELLOW}[!] To enable: export GEMINI_API_KEY='your-api-key'${NC}\n"
else
    echo -e "${GREEN}[+] Gemini API key detected - AI enrichment enabled${NC}\n"
fi

# ============================================================================
# STEP 4: PARSE & ENRICH FINDINGS
# ============================================================================

echo -e "${BLUE}[STEP 4/5] Parsing & Enriching Findings${NC}\n"

if [ ! -f "parser.py" ]; then
    echo -e "${RED}Error: parser.py not found${NC}"
    exit 1
fi

python3 parser.py "$SCAN_JSON" "$REPTOR_JSON"

if [ ! -f "$REPTOR_JSON" ]; then
    echo -e "${RED}Error: Failed to generate SysReptor JSON${NC}"
    exit 1
fi

echo -e "\n${GREEN}[+] Findings parsed and enriched successfully${NC}"
echo -e "${GREEN}[+] SysReptor-ready JSON: ${REPTOR_JSON}${NC}\n"

# ============================================================================
# STEP 5: CREATE PROJECT & EXPORT TO SYSREPTOR
# ============================================================================

echo -e "${BLUE}[STEP 5/5] Creating SysReptor Project & Exporting${NC}\n"

# Get project name from user
read -p "Enter SysReptor project name (or press Enter for default): " PROJECT_NAME

if [ -z "$PROJECT_NAME" ]; then
    PROJECT_NAME="Security Scan - ${RESOURCE_NAME} - $(date +%Y-%m-%d_%H:%M)"
    echo -e "${YELLOW}[!] Using default name: ${PROJECT_NAME}${NC}"
fi

# Check for template ID
if [ -n "$REPTOR_TEMPLATE_ID" ]; then
    echo -e "${GREEN}[+] Using template ID: ${REPTOR_TEMPLATE_ID}${NC}"
    TEMPLATE_ARG="--template $REPTOR_TEMPLATE_ID"
else
    echo -e "${YELLOW}[!] No template specified - using default${NC}"
    echo -e "${YELLOW}[!] Set REPTOR_TEMPLATE_ID to use a specific template${NC}"
    TEMPLATE_ARG=""
fi

# Create new project in SysReptor
echo -e "${YELLOW}[*] Creating new project in SysReptor...${NC}"
PROJECT_RESPONSE=$(reptor createproject --name "$PROJECT_NAME" $TEMPLATE_ARG --format json 2>&1)

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to create project${NC}"
    echo -e "${RED}${PROJECT_RESPONSE}${NC}"
    exit 1
fi

# Extract project ID from response
PROJECT_ID=$(echo "$PROJECT_RESPONSE" | jq -r '.id' 2>/dev/null)

if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" = "null" ]; then
    echo -e "${RED}Error: Could not extract project ID${NC}"
    echo -e "${YELLOW}Response: ${PROJECT_RESPONSE}${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Project created successfully${NC}"
echo -e "${GREEN}[+] Project ID: ${PROJECT_ID}${NC}"

# Set the project ID for pushing
export REPTOR_PROJECT_ID="$PROJECT_ID"

# Push findings to the newly created project
echo -e "${YELLOW}[*] Pushing findings to SysReptor...${NC}"
cat "$REPTOR_JSON" | reptor pushproject

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to push findings to SysReptor${NC}"
    exit 1
fi

# ============================================================================
# COMPLETION SUMMARY
# ============================================================================

echo -e "\n${CYAN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    WORKFLOW COMPLETED                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}✓ Security scan completed${NC}"
echo -e "${GREEN}✓ Findings parsed and enriched${NC}"
echo -e "${GREEN}✓ Project created in SysReptor${NC}"
echo -e "${GREEN}✓ Findings pushed successfully${NC}\n"

echo -e "${CYAN}Summary:${NC}"
echo -e "  Target URL:        ${TARGET_URL}"
echo -e "  Scan Results:      ${SCAN_JSON}"
echo -e "  HTML Report:       ${SCAN_HTML}"
echo -e "  SysReptor JSON:    ${REPTOR_JSON}"
echo -e "  Project Name:      ${PROJECT_NAME}"
echo -e "  Project ID:        ${PROJECT_ID}"

if [ -n "$GEMINI_API_KEY" ]; then
    echo -e "  AI Enrichment:     ${GREEN}Enabled${NC}"
else
    echo -e "  AI Enrichment:     ${YELLOW}Disabled${NC}"
fi

if [ -n "$REPTOR_TEMPLATE_ID" ]; then
    echo -e "  Template Used:     ${REPTOR_TEMPLATE_ID}"
else
    echo -e "  Template Used:     Default"
fi

echo -e "\n${CYAN}Next Steps:${NC}"
echo -e "  1. Review findings in SysReptor"
echo -e "  2. Check HTML report: ${SCAN_HTML}"
echo -e "  3. Update finding statuses in SysReptor as needed"

echo -e "\n${GREEN}All done! 🎉${NC}\n"
 