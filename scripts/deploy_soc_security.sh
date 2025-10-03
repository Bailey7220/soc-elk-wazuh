#!/usr/bin/env bash
set -euo pipefail

# SOC ELK Wazuh Complete Security Deployment Script
# This script runs all security components in the correct order

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

step() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] STEP: $1${NC}"
}

success() {
    echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
}

# Banner
echo -e "${CYAN}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                     SOC ELK WAZUH SECURITY DEPLOYMENT                       ║
║                           Complete Security Setup                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

log "Starting complete SOC security deployment..."
log "Script directory: ${SCRIPT_DIR}"

# Step 1: Generate certificates
step "Step 1/4: Generating SSL/TLS certificates"
if [[ -f "${SCRIPT_DIR}/generate_certs.sh" ]]; then
    bash "${SCRIPT_DIR}/generate_certs.sh"
    success "Certificates generated successfully"
else
    error "generate_certs.sh not found in ${SCRIPT_DIR}"
fi

# Step 2: Install and configure ELK with security
step "Step 2/4: Installing and configuring ELK stack with security"
if [[ -f "${SCRIPT_DIR}/install_elk.sh" ]]; then
    bash "${SCRIPT_DIR}/install_elk.sh"
    success "ELK stack configured successfully"
else
    error "install_elk.sh not found in ${SCRIPT_DIR}"
fi

# Step 3: Install and configure Wazuh with security
step "Step 3/4: Installing and configuring Wazuh with security"
if [[ -f "${SCRIPT_DIR}/install_wazuh.sh" ]]; then
    bash "${SCRIPT_DIR}/install_wazuh.sh"
    success "Wazuh configured successfully"
else
    error "install_wazuh.sh not found in ${SCRIPT_DIR}"
fi

# Step 4: Configure Kibana with security and Wazuh plugin
step "Step 4/4: Configuring Kibana with security and Wazuh integration"
if [[ -f "${SCRIPT_DIR}/configure_kibana.sh" ]]; then
    bash "${SCRIPT_DIR}/configure_kibana.sh"
    success "Kibana configured successfully"
else
    error "configure_kibana.sh not found in ${SCRIPT_DIR}"
fi

# Final verification
step "Running final verification..."

# Check services
log "Verifying service status..."
for service in elasticsearch kibana wazuh-manager filebeat; do
    if systemctl is-active --quiet "${service}"; then
        log "✓ ${service} is running"
    else
        warn "✗ ${service} is not running"
    fi
done

# Check SSL endpoints
log "Verifying SSL endpoints..."
if curl -k -s https://localhost:9200 | grep -q "security_exception"; then
    log "✓ Elasticsearch HTTPS endpoint is secured"
fi

if curl -k -s https://localhost:5601/api/status | grep -q "available"; then
    log "✓ Kibana HTTPS endpoint is accessible"
fi

# Create health check script
log "Creating system health check script..."
cat > /usr/local/bin/soc-health-check << 'EOF'
#!/bin/bash
# SOC Stack Health Check Script

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_service() {
    local service="$1"
    local port="$2"
    local protocol="$3"
    
    echo -n "Checking $service... "
    
    if systemctl is-active --quiet "$service"; then
        if [[ -n "$port" ]]; then
            if [[ "$protocol" == "https" ]]; then
                if curl -k -s "$protocol://localhost:$port" >/dev/null 2>&1; then
                    echo -e "${GREEN}✓ Running and accessible${NC}"
                else
                    echo -e "${YELLOW}⚠ Running but not accessible${NC}"
                fi
            else
                if netstat -tuln | grep -q ":$port"; then
                    echo -e "${GREEN}✓ Running and listening${NC}"
                else
                    echo -e "${YELLOW}⚠ Running but not listening${NC}"
                fi
            fi
        else
            echo -e "${GREEN}✓ Running${NC}"
        fi
    else
        echo -e "${RED}✗ Not running${NC}"
    fi
}

echo "SOC Stack Health Check"
echo "======================"
echo

check_service "elasticsearch" "9200" "https"
check_service "kibana" "5601" "https"
check_service "wazuh-manager" "1514"
check_service "filebeat"

echo
echo "SSL Certificate Status:"
echo "======================"

for cert in /etc/ssl/soc-certs/*/ca-cert.pem /etc/ssl/soc-certs/*/*-cert.pem; do
    if [[ -f "$cert" ]]; then
        cert_name=$(basename "$(dirname "$cert")")
        if openssl x509 -in "$cert" -checkend 2592000 -noout 2>/dev/null; then
            echo -e "$cert_name: ${GREEN}✓ Valid (>30 days)${NC}"
        elif openssl x509 -in "$cert" -checkend 86400 -noout 2>/dev/null; then
            echo -e "$cert_name: ${YELLOW}⚠ Expires soon (<30 days)${NC}"
        else
            echo -e "$cert_name: ${RED}✗ Expired${NC}"
        fi
    fi
done

echo
echo "System Resources:"
echo "================="
echo "Memory Usage:"
free -h | grep -E "(Mem|Swap)"

echo "Disk Usage:"
df -h / /var/lib/elasticsearch /var/log 2>/dev/null

echo
echo "Network Ports:"
echo "=============="
netstat -tuln | grep -E ":(9200|5601|1514|1515)" | sort
EOF

chmod +x /usr/local/bin/soc-health-check

# Display summary
echo
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                          🎉 DEPLOYMENT SUCCESSFUL! 🎉                          ║${NC}"
echo -e "${GREEN}║               SOC ELK Wazuh Security Stack is now operational                  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${YELLOW}🌐 Kibana Web Interface: ${NC}https://$(hostname -I | awk '{print $1}'):5601"
echo -e "${YELLOW}👤 Default Admin User: ${NC}elastic"
if [[ -f "/etc/elasticsearch/passwords.txt" ]]; then
    ELASTIC_PASSWORD=$(grep "^elastic:" /etc/elasticsearch/passwords.txt 2>/dev/null | cut -d: -f2 || echo "Check /etc/elasticsearch/passwords.txt")
    echo -e "${YELLOW}🔑 Admin Password: ${NC}${ELASTIC_PASSWORD}"
else
    echo -e "${YELLOW}🔑 Admin Password: ${NC}Check /etc/elasticsearch/passwords.txt"
fi
echo
echo -e "${YELLOW}📋 Important Files:${NC}"
echo -e "   • SSL Certificates: /etc/ssl/soc-certs/"
echo -e "   • User Passwords: /etc/elasticsearch/passwords.txt"
echo -e "   • Wazuh Agent Password: /var/ossec/etc/authd.pass"
echo
echo -e "${YELLOW}🛠️  Management Commands:${NC}"
echo -e "   • Health Check: /usr/local/bin/soc-health-check"
echo -e "   • Test Agent Enrollment: /usr/local/bin/test-agent-enrollment"
echo -e "   • Check Service Status: systemctl status elasticsearch kibana wazuh-manager"
echo
echo -e "${RED}⚠️  IMPORTANT SECURITY REMINDERS:${NC}"
echo -e "   • Change default passwords immediately"
echo -e "   • Secure the passwords files"
echo -e "   • Configure firewall rules"
echo -e "   • Set up regular backups"
echo

success "Complete SOC security deployment finished successfully!"
log "Run 'sudo /usr/local/bin/soc-health-check' to verify all services"
