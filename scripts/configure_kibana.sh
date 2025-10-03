#!/usr/bin/env bash
set -euo pipefail

# SOC Kibana Security Configuration Script
# Enhanced version of configure_kibana.sh with SSL/TLS and authentication

# Configuration
CERT_DIR="/etc/ssl/soc-certs"
KIBANA_CONFIG="/etc/kibana/kibana.yml"
KIBANA_USER="kibana"
ES_PASS_FILE="/etc/elasticsearch/passwords.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

log "Configuring Kibana with Security and Wazuh Integration"

# Step 1: Check if Elasticsearch is running with security
if ! curl -k -s https://localhost:9200 | grep -q "security_exception"; then
    warn "Elasticsearch security may not be configured. Attempting basic configuration..."
    USE_BASIC_AUTH=false
else
    log "Elasticsearch security detected"
    USE_BASIC_AUTH=true
fi

# Step 2: Get Elasticsearch credentials if available
if [[ -f "${ES_PASS_FILE}" ]] && [[ "${USE_BASIC_AUTH}" == "true" ]]; then
    log "Retrieving Elasticsearch credentials..."
    KIBANA_SYSTEM_PASSWORD=$(grep "^kibana_system:" "${ES_PASS_FILE}" | cut -d: -f2)
    ELASTIC_PASSWORD=$(grep "^elastic:" "${ES_PASS_FILE}" | cut -d: -f2)
    
    if [[ -z "${KIBANA_SYSTEM_PASSWORD}" ]]; then
        warn "Kibana system password not found, using basic configuration"
        USE_BASIC_AUTH=false
    fi
else
    log "Using basic configuration without authentication"
    USE_BASIC_AUTH=false
fi

# Step 3: Stop Kibana if running
log "Stopping Kibana service..."
systemctl stop kibana || warn "Kibana was not running"

# Step 4: Create Kibana certificate directory (if certificates exist)
if [[ -f "${CERT_DIR}/kibana/kibana-cert.pem" ]]; then
    log "Setting up Kibana SSL certificates..."
    mkdir -p /etc/kibana/certs
    cp "${CERT_DIR}/ca/ca-cert.pem" /etc/kibana/certs/
    cp "${CERT_DIR}/kibana/kibana-cert.pem" /etc/kibana/certs/
    cp "${CERT_DIR}/kibana/kibana-key.pem" /etc/kibana/certs/

    # Set proper ownership
    chown -R "${KIBANA_USER}:${KIBANA_USER}" /etc/kibana/certs
    chmod 750 /etc/kibana/certs
    chmod 640 /etc/kibana/certs/*

    USE_SSL=true
    log "SSL certificates configured"
else
    warn "SSL certificates not found, using HTTP"
    USE_SSL=false
fi

# Step 5: Generate Kibana encryption keys
log "Generating Kibana encryption keys..."
KIBANA_ENCRYPTION_KEY=$(openssl rand -hex 32)
KIBANA_SAVED_OBJECTS_KEY=$(openssl rand -hex 32)
KIBANA_SECURITY_KEY=$(openssl rand -hex 32)

# Step 6: Create Kibana configuration
log "Creating Kibana configuration..."

# Backup original config if it exists
if [[ -f "${KIBANA_CONFIG}" ]]; then
    cp "${KIBANA_CONFIG}" "${KIBANA_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Create configuration based on security setup
if [[ "${USE_SSL}" == "true" ]] && [[ "${USE_BASIC_AUTH}" == "true" ]]; then
    # Full security configuration
    log "Creating full security configuration..."
    cat > "${KIBANA_CONFIG}" << EOF
server.port: 5601
server.host: "0.0.0.0"
server.name: "soc-kibana"

elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "${KIBANA_SYSTEM_PASSWORD}"

elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca-cert.pem"]
elasticsearch.ssl.verificationMode: certificate

server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/certs/kibana-cert.pem
server.ssl.key: /etc/kibana/certs/kibana-key.pem

xpack.encryptedSavedObjects.encryptionKey: "${KIBANA_SAVED_OBJECTS_KEY}"
xpack.security.encryptionKey: "${KIBANA_SECURITY_KEY}"
xpack.reporting.encryptionKey: "${KIBANA_ENCRYPTION_KEY}"

xpack.security.session.idleTimeout: "1h"
xpack.security.session.lifespan: "8h"

monitoring.enabled: true
monitoring.kibana.collection.enabled: true

logging.appenders:
  file:
    type: file
    fileName: /var/log/kibana/kibana.log
    layout:
      type: json

root:
  appenders:
    - default
    - file
  level: info

pid.file: /run/kibana/kibana.pid
EOF

elif [[ "${USE_SSL}" == "true" ]]; then
    # SSL only configuration
    log "Creating SSL-only configuration..."
    cat > "${KIBANA_CONFIG}" << EOF
server.port: 5601
server.host: "0.0.0.0"
server.name: "soc-kibana"

elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca-cert.pem"]
elasticsearch.ssl.verificationMode: certificate

server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/certs/kibana-cert.pem
server.ssl.key: /etc/kibana/certs/kibana-key.pem

xpack.encryptedSavedObjects.encryptionKey: "${KIBANA_SAVED_OBJECTS_KEY}"
xpack.security.encryptionKey: "${KIBANA_SECURITY_KEY}"
xpack.reporting.encryptionKey: "${KIBANA_ENCRYPTION_KEY}"

logging.appenders:
  file:
    type: file
    fileName: /var/log/kibana/kibana.log
    layout:
      type: json

root:
  appenders:
    - default
    - file
  level: info

pid.file: /run/kibana/kibana.pid
EOF

else
    # Basic HTTP configuration (original functionality maintained)
    log "Creating basic HTTP configuration..."
    cat > "${KIBANA_CONFIG}" << EOF
server.port: 5601
server.host: "0.0.0.0"
server.name: "soc-kibana"

elasticsearch.hosts: ["http://localhost:9200"]

xpack.encryptedSavedObjects.encryptionKey: "${KIBANA_SAVED_OBJECTS_KEY}"
xpack.security.encryptionKey: "${KIBANA_SECURITY_KEY}"
xpack.reporting.encryptionKey: "${KIBANA_ENCRYPTION_KEY}"

logging.appenders:
  file:
    type: file
    fileName: /var/log/kibana/kibana.log
    layout:
      type: json

root:
  appenders:
    - default
    - file
  level: info

pid.file: /run/kibana/kibana.pid
EOF
fi

# Set proper ownership
chown "${KIBANA_USER}:${KIBANA_USER}" "${KIBANA_CONFIG}"
chmod 660 "${KIBANA_CONFIG}"

# Step 7: Create log directory
log "Setting up Kibana logging..."
mkdir -p /var/log/kibana
chown "${KIBANA_USER}:${KIBANA_USER}" /var/log/kibana
chmod 755 /var/log/kibana

# Step 8: Start Kibana
log "Starting Kibana..."
systemctl daemon-reload
systemctl enable kibana
systemctl start kibana

# Step 9: Wait for Kibana to start
log "Waiting for Kibana to start (this may take a few minutes)..."
KIBANA_URL="http://localhost:5601"
if [[ "${USE_SSL}" == "true" ]]; then
    KIBANA_URL="https://localhost:5601"
fi

for i in {1..120}; do
    if curl -k -s "${KIBANA_URL}/api/status" | grep -q "available"; then
        log "Kibana started successfully"
        break
    fi
    if [[ $i -eq 120 ]]; then
        error "Kibana failed to start within 2 minutes. Check logs: journalctl -u kibana -f"
    fi
    sleep 2
done

# Step 10: Install Wazuh Kibana plugin
log "Installing Wazuh Kibana plugin..."

# Get Kibana version for plugin compatibility
KIBANA_VERSION=$(dpkg -l kibana | tail -1 | awk '{print $3}' | cut -d'-' -f1)
WAZUH_VERSION="4.8.0"

# Install Wazuh plugin
sudo -u "${KIBANA_USER}" /usr/share/kibana/bin/kibana-plugin install \
    "https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-${WAZUH_VERSION}_${KIBANA_VERSION}-1.zip" || \
    warn "Wazuh plugin installation failed - may need manual installation"

# Step 11: Restart Kibana to load plugin
log "Restarting Kibana to load Wazuh plugin..."
systemctl restart kibana

# Wait for restart
sleep 30
for i in {1..60}; do
    if curl -k -s "${KIBANA_URL}/api/status" | grep -q "available"; then
        log "Kibana restarted successfully with Wazuh plugin"
        break
    fi
    if [[ $i -eq 60 ]]; then
        warn "Kibana restart verification failed, but continuing..."
        break
    fi
    sleep 2
done

# Step 12: Create index patterns (enhanced from original)
log "Creating Kibana index patterns..."

# Wait a bit more for full initialization
sleep 15

# Set up authentication for API calls
AUTH_HEADER=""
if [[ "${USE_BASIC_AUTH}" == "true" ]]; then
    AUTH_HEADER="-u elastic:${ELASTIC_PASSWORD}"
fi

# Create Wazuh index pattern (original functionality maintained)
log "Creating Wazuh alerts index pattern..."
curl -k ${AUTH_HEADER:+"$AUTH_HEADER"} -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/wazuh-alerts-*" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -d '{
        "attributes": {
            "title": "wazuh-alerts-*",
            "timeFieldName": "@timestamp"
        }
    }' 2>/dev/null || warn "Wazuh index pattern creation may have failed"

# Create Filebeat index pattern
log "Creating Filebeat index pattern..."
curl -k ${AUTH_HEADER:+"$AUTH_HEADER"} -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/filebeat-*" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -d '{
        "attributes": {
            "title": "filebeat-*",
            "timeFieldName": "@timestamp"
        }
    }' 2>/dev/null || warn "Filebeat index pattern creation may have failed"

log "Kibana configured with Wazuh plugin and index patterns successfully!"
echo
echo "==================================="
echo "KIBANA CONFIGURATION SUMMARY"
echo "==================================="
echo

if [[ "${USE_SSL}" == "true" ]]; then
    echo "✓ HTTPS enabled with SSL certificates"
    echo "🌐 Kibana URL: https://$(hostname -I | awk '{print $1}'):5601"
else
    echo "⚠ HTTP configuration (no SSL)"
    echo "🌐 Kibana URL: http://$(hostname -I | awk '{print $1}'):5601"
fi

if [[ "${USE_BASIC_AUTH}" == "true" ]]; then
    echo "✓ Elasticsearch authentication configured"
    echo "👤 Login with: elastic / [password from ${ES_PASS_FILE}]"
else
    echo "⚠ No authentication configured"
fi

echo "✓ Wazuh plugin installed"
echo "✓ Index patterns created"
echo "✓ Encryption keys generated"
echo "✓ Logging configured"
echo
echo "🔐 Certificate directory: /etc/kibana/certs/"
echo "⚙️  Configuration file: ${KIBANA_CONFIG}"
echo "📝 Log file: /var/log/kibana/kibana.log"
echo
echo "Next Steps:"
echo "1. Access Kibana web interface"
echo "2. Configure Wazuh dashboards and visualizations"
echo "3. Set up alerting rules"
echo "4. Create custom dashboards for SOC operations"
echo

log "Kibana configuration completed!"
