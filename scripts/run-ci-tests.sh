#!/bin/bash

# Local CI Test Runner (Bash version)
# Runs the same test suite as GitHub Actions CI/CD pipeline

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
WITH_XGT=false
XGT_VERSION="latest"
FAIL_FAST=false
SECURITY_SCANS=false
XGT_CONTAINER=""
XGT_PORT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --with-xgt)
            WITH_XGT=true
            shift
            ;;
        --xgt-version)
            XGT_VERSION="$2"
            shift 2
            ;;
        --fail-fast)
            FAIL_FAST=true
            shift
            ;;
        --security-scans)
            SECURITY_SCANS=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --with-xgt              Include XGT integration tests"
            echo "  --xgt-version VERSION   XGT Docker image version (default: latest)"
            echo "  --fail-fast            Stop on first failure"
            echo "  --security-scans       Include security scans"
            echo "  --help                 Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                          # Basic test suite"
            echo "  $0 --with-xgt              # Include XGT tests"
            echo "  $0 --with-xgt --xgt-version 2.3.0  # Specific XGT version"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Test results tracking
declare -A test_results
total_tests=0
passed_tests=0
start_time=$(date +%s)

log() {
    local color=${2:-$NC}
    echo -e "${color}$1${NC}"
}

run_test() {
    local name="$1"
    local cmd="$2"
    
    log "🔄 Running: $name" $BLUE
    total_tests=$((total_tests + 1))
    
    if eval "$cmd"; then
        log "✅ $name - PASSED" $GREEN
        test_results["$name"]="PASSED"
        passed_tests=$((passed_tests + 1))
        return 0
    else
        log "❌ $name - FAILED" $RED
        test_results["$name"]="FAILED"
        if [ "$FAIL_FAST" = true ]; then
            log "💥 Stopping due to --fail-fast" $RED
            cleanup_xgt
            exit 1
        fi
        return 1
    fi
}

cleanup_xgt() {
    if [ ! -z "$XGT_CONTAINER" ]; then
        log "🧹 Cleaning up XGT container..." $YELLOW
        docker stop "$XGT_CONTAINER" 2>/dev/null || true
        docker rm "$XGT_CONTAINER" 2>/dev/null || true
    fi
}

# Cleanup on exit
trap cleanup_xgt EXIT

setup_xgt() {
    if [ "$WITH_XGT" != true ]; then
        return 0
    fi
    
    log "🚀 Setting up XGT server..." $PURPLE
    
    # Pull XGT image
    log "📦 Pulling rocketgraph/xgt:${XGT_VERSION}..." $BLUE
    if ! docker pull "rocketgraph/xgt:${XGT_VERSION}"; then
        log "❌ Failed to pull XGT image" $RED
        return 1
    fi
    
    # Find available port
    for port in {4367..4377}; do
        if ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
            XGT_PORT=$port
            log "📍 Using XGT port: $port" $BLUE
            break
        fi
    done
    
    if [ -z "$XGT_PORT" ]; then
        XGT_PORT=$(shuf -i 5000-5999 -n 1)
        log "📍 Using fallback XGT port: $XGT_PORT" $YELLOW
    fi
    
    # Start XGT container
    XGT_CONTAINER="ci-test-xgt-$(date +%s)"
    
    log "🏃 Starting XGT container..." $BLUE
    if ! docker run -d \
        --name "$XGT_CONTAINER" \
        -p "$XGT_PORT:4367" \
        "rocketgraph/xgt:${XGT_VERSION}"; then
        log "❌ Failed to start XGT container" $RED
        return 1
    fi
    
    # Wait for XGT to be ready
    log "⏳ Waiting for XGT server to be ready..." $BLUE
    for i in {1..40}; do
        if curl -f "http://localhost:${XGT_PORT}/health" >/dev/null 2>&1; then
            log "✅ XGT server is ready!" $GREEN
            return 0
        fi
        sleep 3
    done
    
    log "❌ XGT server failed to start" $RED
    log "📋 XGT logs:" $YELLOW
    docker logs "$XGT_CONTAINER" || true
    return 1
}

print_summary() {
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    log "\n${'='*60}" $BOLD
    log "📊 TEST RESULTS SUMMARY" $BOLD
    log "${'='*60}" $BOLD
    
    for test_name in "${!test_results[@]}"; do
        local result="${test_results[$test_name]}"
        if [ "$result" = "PASSED" ]; then
            log "✅ PASS $test_name" $GREEN
        else
            log "❌ FAIL $test_name" $RED
        fi
    done
    
    log "\n📈 Overall: $passed_tests/$total_tests tests passed" \
        $([ $passed_tests -eq $total_tests ] && echo $GREEN || echo $RED)
    log "⏱️  Total time: ${elapsed}s" $BLUE
    
    if [ $passed_tests -eq $total_tests ]; then
        log "\n🎉 All tests passed! Ready for CI/CD" $GREEN
        return 0
    else
        local failed=$((total_tests - passed_tests))
        log "\n💥 $failed test(s) failed" $RED
        return 1
    fi
}

main() {
    log "🚀 Starting Local CI Test Suite" $BOLD
    log "Project: $(pwd)" $BLUE
    
    # Check requirements
    log "🔍 Checking requirements..." $PURPLE
    for tool in python3 pip; do
        if ! command -v "$tool" >/dev/null; then
            log "❌ Missing required tool: $tool" $RED
            exit 1
        fi
    done
    
    if [ "$WITH_XGT" = true ] && ! command -v docker >/dev/null; then
        log "❌ Docker required for XGT tests" $RED
        exit 1
    fi
    
    # Setup environment
    log "🐍 Setting up Python environment..." $PURPLE
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements/development.txt
    
    # Setup XGT if needed
    if [ "$WITH_XGT" = true ]; then
        if ! setup_xgt; then
            log "💥 XGT setup failed" $RED
            exit 1
        fi
    fi
    
    # Run test suite
    log "\n🧪 Running Test Suite..." $BOLD
    
    # Code Quality & Security Checks
    log "\n🔍 Code Quality & Security Checks" $PURPLE
    run_test "Ruff lint check" "python3 -m ruff check . --output-format=github"
    run_test "Ruff format check" "python3 -m ruff format --check ."
    run_test "MyPy type check" "python3 -m mypy app/ --ignore-missing-imports"
    run_test "Bandit security scan" "python3 -m bandit -r app/ -f json -o bandit-report.json"
    
    # Unit Tests
    log "\n🧪 Unit Tests" $PURPLE
    run_test "Unit tests" "python3 -m pytest tests/unit/ --cov=app --cov-report=xml --cov-report=html --cov-fail-under=20 --junitxml=junit.xml -v"
    
    # Mock Integration Tests
    log "\n🔗 Mock Integration Tests" $PURPLE
    run_test "Mock integration tests" "python3 -m pytest tests/integration/test_api_endpoints.py --junitxml=mock-integration-junit.xml -v"
    
    # XGT Integration Tests
    if [ "$WITH_XGT" = true ]; then
        log "\n🧪 XGT Integration Tests" $PURPLE
        XGT_HOST=localhost XGT_PORT=$XGT_PORT XGT_USERNAME=admin XGT_PASSWORD="" ENVIRONMENT=testing \
        run_test "XGT integration tests" "python3 -m pytest tests/integration/test_xgt_datasets.py --junitxml=xgt-integration-junit.xml -v -s"
    fi
    
    # Security Scans
    if [ "$SECURITY_SCANS" = true ]; then
        log "\n🔒 Security Scans" $PURPLE
        run_test "Safety dependency scan" "python3 -m safety check"
    fi
    
    # Print summary
    print_summary
}

main "$@"