#!/bin/bash

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== SysReptor Project Creator & Exporter ===${NC}\n"

# Load .env file if present
if [ -f ".env" ]; then
    set -o allexport
    source .env
    set +o allexport
    echo -e "${GREEN}[+] Loaded configuration from .env${NC}"
else
    echo -e "${YELLOW}[!] No .env file found — relying on existing environment variables${NC}"
fi

# Check if reptor-ready.json exists
if [ ! -f "reptor-ready.json" ]; then
    echo -e "${RED}Error: reptor-ready.json not found${NC}"
    echo -e "${YELLOW}Run parser.py first to generate reptor-ready.json${NC}"
    exit 1
fi

# Setup virtual environment
echo -e "${BLUE}[*] Setting up Python virtual environment...${NC}"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

# Ensure reptor is installed
if ! command -v reptor &> /dev/null; then
    echo -e "${BLUE}[*] Installing reptor...${NC}"
    pip install -q reptor
fi

# Get project name
read -p "Enter project name: " PROJECT_NAME

if [ -z "$PROJECT_NAME" ]; then
    PROJECT_NAME="Security Assessment - $(date +%Y-%m-%d)"
    echo -e "${YELLOW}[!] Using default name: ${PROJECT_NAME}${NC}"
fi

# Template handling
if [ -n "$REPTOR_TEMPLATE_ID" ]; then
    echo -e "${GREEN}[+] Using template ID: ${REPTOR_TEMPLATE_ID}${NC}"
    TEMPLATE_ARG="--template $REPTOR_TEMPLATE_ID"
else
    echo -e "${YELLOW}[!] No template specified. Using default template.${NC}"
    TEMPLATE_ARG=""
fi

# Validate required reptor config
if [ -z "$REPTOR_SERVER" ]; then
    echo -e "${RED}Error: REPTOR_SERVER is not set in .env${NC}"
    exit 1
fi

if [ -z "$REPTOR_API_KEY" ]; then
    echo -e "${RED}Error: REPTOR_API_KEY is not set in .env${NC}"
    exit 1
fi

REPTOR_ARGS="--server $REPTOR_SERVER --token $REPTOR_API_KEY"

# Design ID (required by reptor createproject)
if [ -z "$REPTOR_DESIGN_ID" ]; then
    echo -e "${RED}Error: REPTOR_DESIGN_ID is not set in .env${NC}"
    exit 1
fi

# Create project
echo -e "\n${BLUE}[*] Creating new project in SysReptor...${NC}"

set +e
PROJECT_RESPONSE=$(reptor $REPTOR_ARGS createproject --name "$PROJECT_NAME" -d "$REPTOR_DESIGN_ID" $TEMPLATE_ARG 2>&1)
CREATE_EXIT=$?
set -e

echo -e "${YELLOW}[debug] exit code: ${CREATE_EXIT}${NC}"
echo -e "${YELLOW}[debug] reptor response: ${PROJECT_RESPONSE}${NC}"

if [ $CREATE_EXIT -ne 0 ]; then
    echo -e "${RED}Error: reptor createproject failed (exit code ${CREATE_EXIT})${NC}"
    exit 1
fi

# Extract UUID from CLI output
PROJECT_ID=$(echo "$PROJECT_RESPONSE" | grep -oE '[0-9a-fA-F-]{36}' | head -n 1)

if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}Error: Could not extract project ID from response${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Project created successfully${NC}"
echo -e "${GREEN}[+] Project ID: ${PROJECT_ID}${NC}"
echo -e "${GREEN}[+] Project Name: ${PROJECT_NAME}${NC}"

# Set project ID for push
export REPTOR_PROJECT_ID="$PROJECT_ID"

# Push findings
echo -e "\n${BLUE}[*] Pushing findings to SysReptor project...${NC}"

if reptor $REPTOR_ARGS pushproject < reptor-ready.json; then
    echo -e "\n${GREEN}=== Export Complete ===${NC}"
    echo -e "${GREEN}[+] Findings successfully pushed${NC}"
    echo -e "${GREEN}[+] Project ID: ${PROJECT_ID}${NC}"
    echo -e "${GREEN}[+] Project Name: ${PROJECT_NAME}${NC}"
else
    echo -e "\n${RED}Error: Failed to push findings${NC}"
    exit 1
fi
