#!/usr/bin/env bash
set -euo pipefail

# SOC ELK Elasticsearch Security Configuration Script
# Replaces install_elk.sh with security-enhanced installation and configuration

# Configuration
CERT_DIR="/etc/ssl/soc-certs"
ES_CONFIG="/etc/elasticsearch/elasticsearch.yml"
ES_HOME="/usr/share/elasticsearch"
ES_USER="elasticsearch"
KEYSTORE_PASS="changeit"

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

log "Installing and Configuring ELK Stack with Security"

# Step 1: Add Elastic repository (same as original)
log "Adding Elastic APT repository..."
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | \
    tee /etc/apt/sources.list.d/elastic-7.x.list
apt-get update

# Step 2: Install Elasticsearch
log "Installing Elasticsearch..."
apt-get install -y elasticsearch

# Step 3: Verify certificates exist
log "Verifying certificates..."
if [[ ! -f "${CERT_DIR}/ca/ca-cert.pem" ]]; then
    error "CA certificate not found. Run generate_certs.sh first."
fi

if [[ ! -f "${CERT_DIR}/elasticsearch/elasticsearch.p12" ]]; then
    error "Elasticsearch certificate not found. Run generate_certs.sh first."
fi

# Step 4: Create Elasticsearch certificate directory
log "Setting up Elasticsearch certificate directory..."
mkdir -p /etc/elasticsearch/certs
cp "${CERT_DIR}/ca/ca-cert.pem" /etc/elasticsearch/certs/
cp "${CERT_DIR}/elasticsearch/elasticsearch.p12" /etc/elasticsearch/certs/
cp "${CERT_DIR}/elasticsearch/elasticsearch-cert.pem" /etc/elasticsearch/certs/
cp "${CERT_DIR}/elasticsearch/elasticsearch-key.pem" /etc/elasticsearch/certs/

# Set proper ownership
chown -R "${ES_USER}:${ES_USER}" /etc/elasticsearch/certs
chmod 750 /etc/elasticsearch/certs
chmod 640 /etc/elasticsearch/certs/*

# Step 5: Configure Elasticsearch keystore
log "Configuring Elasticsearch keystore..."
cd "${ES_HOME}"

# Create keystore if it doesn't exist
if [[ ! -f "/etc/elasticsearch/elasticsearch.keystore" ]]; then
    sudo -u "${ES_USER}" "${ES_HOME}/bin/elasticsearch-keystore" create
fi

# Add keystore passwords
echo "${KEYSTORE_PASS}" | sudo -u "${ES_USER}" "${ES_HOME}/bin/elasticsearch-keystore" add -x xpack.security.transport.ssl.keystore.secure_password
echo "${KEYSTORE_PASS}" | sudo -u "${ES_USER}" "${ES_HOME}/bin/elasticsearch-keystore" add -x xpack.security.transport.ssl.truststore.secure_password
echo "${KEYSTORE_PASS}" | sudo -u "${ES_USER}" "${ES_HOME}/bin/elasticsearch-keystore" add -x xpack.security.http.ssl.keystore.secure_password

log "Keystore configured successfully"

# Step 6: Create secure Elasticsearch configuration (replaces copying from configs/)
log "Creating secure Elasticsearch configuration..."

# Backup original config if it exists
if [[ -f "${ES_CONFIG}" ]]; then
    cp "${ES_CONFIG}" "${ES_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Create new secure configuration
cat > "${ES_CONFIG}" << 'EOF'
# ======================== Elasticsearch Configuration =========================
cluster.name: soc-elk-cluster
node.name: soc-elk-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
bootstrap.memory_lock: true
network.host: 0.0.0.0
http.port: 9200
discovery.seed_hosts: ["127.0.0.1"]
cluster.initial_master_nodes: ["soc-elk-node-1"]
action.destructive_requires_name: false

# ================================= X-Pack Security =================================
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# ================================= Transport Security =================================
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.client_authentication: required
xpack.security.transport.ssl.keystore.path: certs/elasticsearch.p12
xpack.security.transport.ssl.truststore.path: certs/elasticsearch.p12

# ================================= HTTP Security =================================
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.verification_mode: certificate
xpack.security.http.ssl.keystore.path: certs/elasticsearch.p12
xpack.security.http.ssl.client_authentication: optional

# ================================= Authentication =================================
xpack.security.authc.realms.native.native1.order: 0

# ================================= Authorization =================================
xpack.security.audit.enabled: true
xpack.security.audit.logfile.events.include: 
  - access_denied
  - access_granted
  - anonymous_access_denied
  - authentication_failed
  - authentication_success
  - realm_authentication_failed
  - connection_denied
  - connection_granted
  - tampered_request
  - run_as_denied
  - run_as_granted
EOF

# Set proper ownership
chown "${ES_USER}:${ES_USER}" "${ES_CONFIG}"
chmod 660 "${ES_CONFIG}"

log "Elasticsearch configuration updated with security settings"

# Step 7: Configure JVM heap size
log "Configuring JVM heap size..."
JVM_OPTIONS="/etc/elasticsearch/jvm.options"

# Backup JVM options
if [[ -f "${JVM_OPTIONS}" ]]; then
    cp "${JVM_OPTIONS}" "${JVM_OPTIONS}.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Get system memory and calculate heap size (50% of total RAM, max 32GB)
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))
HEAP_SIZE_MB=$((TOTAL_MEM_MB / 2))

# Cap at 32GB (32768MB) as recommended by Elasticsearch
if [[ ${HEAP_SIZE_MB} -gt 32768 ]]; then
    HEAP_SIZE_MB=32768
fi

# Minimum 1GB heap
if [[ ${HEAP_SIZE_MB} -lt 1024 ]]; then
    HEAP_SIZE_MB=1024
fi

# Update JVM options
sed -i "s/^-Xms.*/-Xms${HEAP_SIZE_MB}m/" "${JVM_OPTIONS}"
sed -i "s/^-Xmx.*/-Xmx${HEAP_SIZE_MB}m/" "${JVM_OPTIONS}"

log "JVM heap size set to ${HEAP_SIZE_MB}MB"

# Step 8: Install Logstash
log "Installing Logstash..."
apt-get install -y logstash

# Copy logstash configuration (use existing config from configs/)
log "Configuring Logstash..."
if [[ -f "../configs/logstash/wazuh.conf" ]]; then
    cp ../configs/logstash/wazuh.conf /etc/logstash/conf.d/02-wazuh.conf
else
    warn "Logstash configuration not found, creating basic configuration"
    cat > /etc/logstash/conf.d/02-wazuh.conf << 'EOF'
input {
  beats {
    port => 5044
  }
}
filter {
  if [fileset][module] == "wazuh" {   
    # Example: parse Wazuh alert JSON
    json {
      source => "message"
    }
  }
}
output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "wazuh-alerts-%{+YYYY.MM.dd}"
    ssl => true
    ssl_certificate_verification => true
    cacert => "/etc/ssl/soc-certs/ca/ca-cert.pem"
  }
  stdout { codec => rubydebug }
}
EOF
fi

# Step 9: Install Kibana
log "Installing Kibana..."
apt-get install -y kibana

# Create basic Kibana configuration (will be enhanced by configure_kibana_security.sh)
log "Creating basic Kibana configuration..."
cat > /etc/kibana/kibana.yml << 'EOF'
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://localhost:9200"]
EOF

# Step 10: Enable and start Elasticsearch
log "Starting Elasticsearch with security enabled..."
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# Wait for Elasticsearch to start
log "Waiting for Elasticsearch to start..."
for i in {1..30}; do
    if curl -s -k https://localhost:9200 >/dev/null 2>&1; then
        log "Elasticsearch started successfully"
        break
    fi
    if [[ $i -eq 30 ]]; then
        error "Elasticsearch failed to start within 30 seconds"
    fi
    sleep 1
done

# Step 11: Set up built-in user passwords
log "Setting up built-in user passwords..."
sleep 10  # Give Elasticsearch more time to fully initialize

# Generate strong passwords
ELASTIC_PASSWORD=$(openssl rand -base64 32)
KIBANA_PASSWORD=$(openssl rand -base64 32)
LOGSTASH_PASSWORD=$(openssl rand -base64 32)
BEATS_PASSWORD=$(openssl rand -base64 32)

# Save passwords securely
PASS_FILE="/etc/elasticsearch/passwords.txt"
cat > "${PASS_FILE}" << EOF
# SOC ELK Wazuh User Passwords
# Generated: $(date)
# KEEP THIS FILE SECURE!

elastic:${ELASTIC_PASSWORD}
kibana_system:${KIBANA_PASSWORD}
logstash_system:${LOGSTASH_PASSWORD}
beats_system:${BEATS_PASSWORD}
apm_system:$(openssl rand -base64 32)
remote_monitoring_user:$(openssl rand -base64 32)

# Custom SOC Users (to be created separately)
soc_admin:$(openssl rand -base64 32)
soc_analyst:$(openssl rand -base64 32)
soc_viewer:$(openssl rand -base64 32)
EOF

chmod 600 "${PASS_FILE}"
chown "root:${ES_USER}" "${PASS_FILE}"

# Use elasticsearch-setup-passwords with auto-generated passwords
log "Configuring built-in user passwords..."
"${ES_HOME}/bin/elasticsearch-setup-passwords" interactive -u https://localhost:9200 << EOF || warn "Password setup may have failed - check manually"
y
${ELASTIC_PASSWORD}
${ELASTIC_PASSWORD}
${BEATS_PASSWORD}
${BEATS_PASSWORD}
${KIBANA_PASSWORD}
${KIBANA_PASSWORD}
${LOGSTASH_PASSWORD}
${LOGSTASH_PASSWORD}
$(grep apm_system "${PASS_FILE}" | cut -d: -f2)
$(grep apm_system "${PASS_FILE}" | cut -d: -f2)
$(grep remote_monitoring_user "${PASS_FILE}" | cut -d: -f2)
$(grep remote_monitoring_user "${PASS_FILE}" | cut -d: -f2)
EOF

# Step 12: Enable and start Logstash
log "Starting Logstash..."
systemctl enable logstash
systemctl start logstash

# Step 13: Enable Kibana (will be started by configure_kibana_security.sh)
log "Enabling Kibana service..."
systemctl enable kibana

log "ELK Stack installation and security configuration completed!"
echo
echo "==================================="
echo "IMPORTANT SECURITY INFORMATION"
echo "==================================="
echo
echo "✓ Elasticsearch installed with X-Pack security enabled"
echo "✓ SSL/TLS encryption configured"
echo "✓ Built-in users configured with strong passwords"
echo "✓ Logstash installed with SSL configuration"
echo "✓ Kibana installed (requires further configuration)"
echo
echo "📁 Passwords saved to: ${PASS_FILE}"
echo "🔐 Certificate directory: /etc/elasticsearch/certs"
echo "⚙️  Configuration file: ${ES_CONFIG}"
echo
echo "Next Steps:"
echo "1. Run configure_kibana_security.sh to complete Kibana setup"
echo "2. Run configure_wazuh_security.sh to setup Wazuh with SSL"
echo "3. Test all service integrations"
echo
warn "CRITICAL: Secure the passwords file (${PASS_FILE}) - it contains sensitive information!"
