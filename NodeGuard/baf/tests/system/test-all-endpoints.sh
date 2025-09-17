#!/bin/bash

# =============================================================================
# NodeGuard BAF - Simple Endpoint Testing Script
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
BASE_URL="http://localhost:3000"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="secure_admin_password_2024"
JWT_TOKEN=""
CSRF_TOKEN=""

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

print_header() {
    echo -e "\n${BLUE}=============================================================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}=============================================================================${NC}\n"
}

print_section() {
    echo -e "\n${PURPLE}📍 $1${NC}\n"
}

print_test() {
    echo -e "${CYAN}🧪 Testing: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
}

print_error() {
    echo -e "${RED}❌ FAIL: $1${NC}"
    echo -e "${RED}   Response: $2${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
}

increment_test() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Simple test function
test_endpoint() {
    local test_name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_status="$4"
    local auth_required="$5"
    local content_type="$6"
    local data="$7"
    
    increment_test
    print_test "$test_name"
    
    # Build curl command
    local curl_cmd="curl -s -w '%{http_code}' -o /tmp/response.txt"
    
    if [[ "$method" != "GET" ]]; then
        curl_cmd="$curl_cmd -X $method"
    fi
    
    if [[ "$auth_required" == "true" && -n "$JWT_TOKEN" ]]; then
        curl_cmd="$curl_cmd -H 'Authorization: Bearer $JWT_TOKEN'"
        # Add CSRF token for POST/PUT/DELETE operations
        if [[ "$method" =~ ^(POST|PUT|DELETE)$ && -n "$CSRF_TOKEN" ]]; then
            curl_cmd="$curl_cmd -H 'X-CSRF-Token: $CSRF_TOKEN'"
        fi
    fi
    
    if [[ -n "$content_type" ]]; then
        curl_cmd="$curl_cmd -H 'Content-Type: $content_type'"
    fi
    
    if [[ -n "$data" ]]; then
        curl_cmd="$curl_cmd -d '$data'"
    fi
    
    curl_cmd="$curl_cmd '$BASE_URL$endpoint'"
    
    # Execute test
    local status_code=$(eval "$curl_cmd" 2>/dev/null || echo "000")
    local response_content=""
    
    if [[ -f "/tmp/response.txt" ]]; then
        response_content=$(cat /tmp/response.txt)
        rm -f /tmp/response.txt
    fi
    
    # Check result
    if [[ "$status_code" == "$expected_status" ]]; then
        print_success "$test_name (Status: $status_code)"
    else
        print_error "$test_name" "Expected: $expected_status, Got: $status_code"
        if [[ -n "$response_content" ]]; then
            echo -e "${YELLOW}   Content: ${response_content:0:100}...${NC}"
        fi
    fi
    
    sleep 0.1
}

# Get authentication token
get_auth_token() {
    print_section "🔑 Getting Authentication Token"
    
    local response=$(curl -s -X POST "$BASE_URL/admin/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USERNAME\",\"password\":\"$ADMIN_PASSWORD\"}")
    
    JWT_TOKEN=$(echo "$response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    CSRF_TOKEN=$(echo "$response" | grep -o '"csrfToken":"[^"]*"' | cut -d'"' -f4)
    
    if [[ -n "$JWT_TOKEN" ]]; then
        echo -e "${GREEN}✅ Authentication token obtained${NC}"
        echo -e "${CYAN}Token: ${JWT_TOKEN:0:30}...${NC}"
        if [[ -n "$CSRF_TOKEN" ]]; then
            echo -e "${CYAN}CSRF Token: ${CSRF_TOKEN:0:20}...${NC}"
        fi
    else
        echo -e "${RED}❌ Failed to get authentication token${NC}"
        echo -e "${RED}   Response: $response${NC}"
    fi
}

# Start testing
print_header "🚀 NodeGuard BAF - Complete Endpoint Testing"
echo -e "Base URL: ${CYAN}$BASE_URL${NC}"
echo -e "Timestamp: ${CYAN}$(date)${NC}\n"

# Check if server is running
echo -e "${CYAN}🔍 Checking if server is running...${NC}"
if curl -s "$BASE_URL/healthz" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Server is running${NC}"
else
    echo -e "${RED}❌ Server is not responding at $BASE_URL${NC}"
    echo -e "${YELLOW}💡 Make sure NodeGuard BAF is running with: npm start${NC}"
    exit 1
fi

# =============================================================================
# 🌐 PUBLIC ENDPOINTS
# =============================================================================
print_section "🌐 Public Endpoints"

# System info
test_endpoint "GET / - System Information" "GET" "/" "200" "false"
test_endpoint "GET / - With Accept Header" "GET" "/" "200" "false"

# Health checks
test_endpoint "GET /healthz - Basic Health" "GET" "/healthz" "200" "false"
test_endpoint "GET /healthz - Detailed Health" "GET" "/healthz?detailed=true" "200" "false"

# Dashboard
test_endpoint "GET /dashboard - Web Dashboard" "GET" "/dashboard" "200" "false"

# Metrics
test_endpoint "GET /metrics - Prometheus Metrics" "GET" "/metrics" "200" "false"

# JSON-RPC endpoints
test_endpoint "POST /rpc - Valid JSON-RPC" "POST" "/rpc" "200" "false" "application/json" '{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}'

test_endpoint "POST /rpc - Batch JSON-RPC" "POST" "/rpc" "200" "false" "application/json" '[{"jsonrpc":"2.0","method":"eth_blockNumber","id":1},{"jsonrpc":"2.0","method":"eth_gasPrice","id":2}]'

test_endpoint "POST /rpc - Invalid JSON" "POST" "/rpc" "400" "false" "application/json" 'invalid json'

test_endpoint "POST /rpc - Empty Body" "POST" "/rpc" "400" "false" "application/json" ''

# Backward compatibility
test_endpoint "POST / - Backward Compatibility" "POST" "/" "307" "false" "application/json" '{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}'

# =============================================================================
# 🔑 AUTHENTICATION
# =============================================================================
print_section "🔑 Authentication Tests"

# Test login
test_endpoint "POST /admin/auth/login - Valid Credentials" "POST" "/admin/auth/login" "200" "false" "application/json" "{\"username\":\"$ADMIN_USERNAME\",\"password\":\"$ADMIN_PASSWORD\"}"

test_endpoint "POST /admin/auth/login - Invalid Credentials" "POST" "/admin/auth/login" "401" "false" "application/json" '{"username":"wrong","password":"wrong"}'

test_endpoint "POST /admin/auth/login - Missing Password" "POST" "/admin/auth/login" "400" "false" "application/json" '{"username":"admin"}'

# Get token for admin tests
get_auth_token

# Test logout
test_endpoint "POST /admin/auth/logout - Without Token" "POST" "/admin/auth/logout" "401" "false"

if [[ -n "$JWT_TOKEN" ]]; then
    test_endpoint "POST /admin/auth/logout - With Valid Token" "POST" "/admin/auth/logout" "200" "true"
    # Get token again for subsequent tests
    get_auth_token
fi

# =============================================================================
# 👑 ADMIN ENDPOINTS
# =============================================================================
print_section "👑 Admin Endpoints"

# Admin panel info (no auth required)
test_endpoint "GET /admin - Panel Information" "GET" "/admin" "200" "false"

# Protected endpoints without auth (should fail)
test_endpoint "GET /admin/health - Without Auth" "GET" "/admin/health" "401" "false"
test_endpoint "GET /admin/stats - Without Auth" "GET" "/admin/stats" "401" "false"
test_endpoint "GET /admin/rules - Without Auth" "GET" "/admin/rules" "401" "false"

# Protected endpoints with auth
if [[ -n "$JWT_TOKEN" ]]; then
    test_endpoint "GET /admin/health - With Auth" "GET" "/admin/health" "200" "true"
    test_endpoint "GET /admin/health - Detailed" "GET" "/admin/health?detailed=true" "200" "true"
    
    test_endpoint "GET /admin/stats - Basic Stats" "GET" "/admin/stats" "200" "true"
    test_endpoint "GET /admin/stats - With Timeframe" "GET" "/admin/stats?timeframe=1h" "200" "true"
    
    test_endpoint "GET /admin/rules - Get Rules" "GET" "/admin/rules" "200" "true"
    test_endpoint "POST /admin/rules - Update Rules" "POST" "/admin/rules" "200" "true" "application/json" '{"meta":{"version":"2.0.0","updated":"2024-01-01T00:00:00Z"},"enforcement":{"mode":"monitor","fail_open":false,"log_level":"info"},"static":{"blockedMethods":["debug_*"],"allowedOrigins":["localhost"]},"heuristics":{"rate_limiting":{"enabled":true,"threshold":100},"pattern_detection":{"enabled":true}}}'
    
    test_endpoint "GET /admin/rules/backups - List Backups" "GET" "/admin/rules/backups" "200" "true"
    test_endpoint "POST /admin/rules/rollback - Rollback Rules" "POST" "/admin/rules/rollback" "200" "true" "application/json" '{"backupId":"latest"}'
    
    # Cache management
    test_endpoint "DELETE /admin/cache/rules - Clear Rules Cache" "DELETE" "/admin/cache/rules" "200" "true"
    test_endpoint "DELETE /admin/cache/reputation - Clear Reputation Cache" "DELETE" "/admin/cache/reputation" "200" "true"
    test_endpoint "DELETE /admin/cache/fingerprint - Clear Fingerprint Cache" "DELETE" "/admin/cache/fingerprint" "200" "true"
    test_endpoint "DELETE /admin/cache/invalid - Invalid Cache Type" "DELETE" "/admin/cache/invalid" "400" "true"
    
    # Reports and security
    test_endpoint "POST /admin/reports/security - Generate Security Report" "POST" "/admin/reports/security" "200" "true" "application/json" '{"timeframe":"24h","format":"json"}'
    test_endpoint "POST /admin/rotate-token - Rotate Token" "POST" "/admin/rotate-token" "200" "true"
    test_endpoint "GET /admin/audit - Audit Logs" "GET" "/admin/audit" "200" "true"
    test_endpoint "GET /admin/audit - Filtered Logs" "GET" "/admin/audit?level=error&limit=10" "200" "true"
fi

# =============================================================================
# 📈 ANALYTICS ENDPOINTS
# =============================================================================
print_section "📈 Analytics Endpoints"

# Without authentication
test_endpoint "GET /api/analytics/top-attackers - No Auth" "GET" "/api/analytics/top-attackers" "401" "false"
test_endpoint "GET /api/analytics/attack-reasons - No Auth" "GET" "/api/analytics/attack-reasons" "401" "false"
test_endpoint "POST /api/analytics/generate-report - No Auth" "POST" "/api/analytics/generate-report" "401" "false"

# With authentication
if [[ -n "$JWT_TOKEN" ]]; then
    test_endpoint "GET /api/analytics/top-attackers - Default" "GET" "/api/analytics/top-attackers" "200" "true"
    test_endpoint "GET /api/analytics/top-attackers - With Limit" "GET" "/api/analytics/top-attackers?limit=5" "200" "true"
    test_endpoint "GET /api/analytics/top-attackers - With Timeframe" "GET" "/api/analytics/top-attackers?timeframe=1h&limit=10" "200" "true"
    
    test_endpoint "GET /api/analytics/attack-reasons - Default" "GET" "/api/analytics/attack-reasons" "200" "true"
    test_endpoint "GET /api/analytics/attack-reasons - With Timeframe" "GET" "/api/analytics/attack-reasons?timeframe=24h" "200" "true"
    
    test_endpoint "POST /api/analytics/generate-report - PDF Report" "POST" "/api/analytics/generate-report" "200" "true" "application/json" '{"format":"pdf","timeframe":"24h"}'
    test_endpoint "POST /api/analytics/generate-report - JSON Report" "POST" "/api/analytics/generate-report" "200" "true" "application/json" '{"format":"json","timeframe":"1h"}'
fi

# =============================================================================
# 🛡️ SECURITY TESTS
# =============================================================================
print_section "🛡️ Security & Error Handling"

# CORS testing
test_endpoint "OPTIONS /admin/health - CORS Preflight" "OPTIONS" "/admin/health" "204" "false"

# Invalid endpoints
test_endpoint "GET /nonexistent - 404 Handling" "GET" "/nonexistent" "404" "false"
test_endpoint "POST /invalid/endpoint - 404 Handling" "POST" "/invalid/endpoint" "404" "false"

# Method validation
test_endpoint "PUT /healthz - Wrong Method" "PUT" "/healthz" "404" "false"
test_endpoint "DELETE /dashboard - Wrong Method" "DELETE" "/dashboard" "404" "false"

# Malformed requests
test_endpoint "POST /rpc - Wrong Content-Type" "POST" "/rpc" "400" "false" "text/plain" '{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}'

# =============================================================================
# 🧪 STRESS TESTS
# =============================================================================
print_section "🧪 Stress & Edge Cases"

# Large payload
test_endpoint "POST /rpc - Large Payload" "POST" "/rpc" "200" "false" "application/json" "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[\"$(printf '%*s' 1000 | tr ' ' 'x')\"],\"id\":1}"

# Unicode testing
test_endpoint "POST /rpc - Unicode Characters" "POST" "/rpc" "200" "false" "application/json" '{"jsonrpc":"2.0","method":"test_unicode","params":["测试数据"],"id":1}'

# =============================================================================
# 🔄 INTEGRATION WORKFLOW
# =============================================================================
print_section "🔄 Integration Workflow Test"

if [[ -n "$JWT_TOKEN" ]]; then
    print_test "Complete Admin Workflow"
    
    # Workflow test
    WORKFLOW_SUCCESS=true
    
    # Get stats
    STATS_STATUS=$(curl -s -H "Authorization: Bearer $JWT_TOKEN" "$BASE_URL/admin/stats" -w '%{http_code}' -o /dev/null)
    if [[ "$STATS_STATUS" != "200" ]]; then
        WORKFLOW_SUCCESS=false
    fi
    
    # Update rules (includes CSRF token)
    RULES_STATUS=$(curl -s -X POST -H "Authorization: Bearer $JWT_TOKEN" -H "X-CSRF-Token: $CSRF_TOKEN" -H "Content-Type: application/json" "$BASE_URL/admin/rules" -d '{"meta":{"version":"2.0.0","updated":"2024-01-01T00:00:00Z"},"enforcement":{"mode":"monitor","fail_open":false,"log_level":"info"},"static":{"blockedMethods":["debug_*"],"allowedOrigins":["localhost"]},"heuristics":{"rate_limiting":{"enabled":true,"threshold":100},"pattern_detection":{"enabled":true}}}' -w '%{http_code}' -o /dev/null)
    if [[ "$RULES_STATUS" != "200" ]]; then
        WORKFLOW_SUCCESS=false
    fi
    
    # Generate report
    REPORT_STATUS=$(curl -s -X POST -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" "$BASE_URL/admin/reports/security" -d '{"timeframe":"1h","format":"json"}' -w '%{http_code}' -o /dev/null)
    if [[ "$REPORT_STATUS" != "200" ]]; then
        WORKFLOW_SUCCESS=false
    fi
    
    increment_test
    if [[ "$WORKFLOW_SUCCESS" == true ]]; then
        print_success "Complete Admin Workflow (Stats: $STATS_STATUS, Rules: $RULES_STATUS, Report: $REPORT_STATUS)"
    else
        print_error "Complete Admin Workflow" "Stats: $STATS_STATUS, Rules: $RULES_STATUS, Report: $REPORT_STATUS"
    fi
else
    print_error "Complete Admin Workflow" "No authentication token available"
    increment_test
fi

# =============================================================================
# 📊 FINAL RESULTS
# =============================================================================
print_header "📊 Test Results Summary"

echo -e "Total Tests: ${CYAN}$TOTAL_TESTS${NC}"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
echo -e "Success Rate: ${CYAN}$SUCCESS_RATE%${NC}"

if [[ $FAILED_TESTS -eq 0 ]]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED! NodeGuard BAF endpoints are working perfectly!${NC}"
    exit 0
else
    echo -e "\n${YELLOW}⚠️  Some tests failed. Check the output above for details.${NC}"
    exit 1
fi
