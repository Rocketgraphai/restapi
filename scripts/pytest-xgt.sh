#!/bin/bash

# Smart pytest wrapper for XGT integration tests
# Usage: ./scripts/pytest-xgt.sh [pytest-args...]
# Example: ./scripts/pytest-xgt.sh tests/integration/test_xgt_datasets.py -v -k "test_datasets_endpoint"

set -e

XGT_VERSION=${XGT_VERSION:-latest}
XGT_PORT=""
CONTAINER_NAME="pytest-xgt-$(date +%s)"
EXISTING_CONTAINER=""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if XGT is already running
check_existing_xgt() {
    for port in {4367..4377}; do
        if curl -s http://localhost:$port/health >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Found existing XGT server on port $port${NC}"
            XGT_PORT=$port
            EXISTING_CONTAINER="true"
            return 0
        fi
    done
    return 1
}

# Cleanup function
cleanup() {
    if [ -z "$EXISTING_CONTAINER" ] && [ ! -z "$CONTAINER_NAME" ]; then
        echo -e "\n${YELLOW}🧹 Cleaning up XGT container...${NC}"
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo -e "${BLUE}🧪 XGT Integration pytest Runner${NC}"

# Check for existing XGT server first
if check_existing_xgt; then
    echo -e "${GREEN}Using existing XGT server${NC}"
else
    echo -e "${BLUE}🚀 Starting new XGT server...${NC}"
    
    # Find available port
    for port in {4367..4377}; do
        if ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
            XGT_PORT=$port
            echo -e "${GREEN}Found available port: $port${NC}"
            break
        fi
    done
    
    if [ -z "$XGT_PORT" ]; then
        XGT_PORT=$(shuf -i 5000-5999 -n 1)
        echo -e "${YELLOW}Using fallback port: $XGT_PORT${NC}"
    fi
    
    # Pull and start XGT
    echo -e "${BLUE}📦 Pulling rocketgraph/xgt:${XGT_VERSION}...${NC}"
    docker pull rocketgraph/xgt:${XGT_VERSION}
    
    echo -e "${BLUE}Starting XGT server on port ${XGT_PORT}...${NC}"
    docker run -d \
        --name $CONTAINER_NAME \
        -p $XGT_PORT:4367 \
        rocketgraph/xgt:${XGT_VERSION}
    
    # Wait for readiness
    echo -e "${BLUE}⏳ Waiting for XGT server...${NC}"
    timeout 120 bash -c "until curl -s http://localhost:${XGT_PORT}/health >/dev/null 2>&1; do 
        sleep 2
    done" || {
        echo -e "${RED}❌ XGT server failed to start${NC}"
        docker logs $CONTAINER_NAME
        exit 1
    }
    
    echo -e "${GREEN}✅ XGT server ready!${NC}"
fi

# Set environment for pytest
export XGT_HOST=localhost
export XGT_PORT=$XGT_PORT
export XGT_USERNAME=admin
export XGT_PASSWORD=""
export ENVIRONMENT=testing

# Run pytest with provided arguments
echo -e "${BLUE}🧪 Running pytest...${NC}"
if [ $# -eq 0 ]; then
    # Default: run all XGT integration tests
    pytest tests/integration/test_xgt_datasets.py -v
else
    # Run with provided arguments
    pytest "$@"
fi