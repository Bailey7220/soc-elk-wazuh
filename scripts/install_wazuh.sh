#!/usr/bin/env bash
set -euo pipefail

# SOC Wazuh Security Installation Script
# This script replaces and enhances the original install_wazuh.sh with security features

# Configuration
CERT_DIR="/etc/ssl/soc-certs"
WAZUH_CONFIG="/var/ossec/etc/ossec.conf"
WAZUH_USER="wazuh"
AUTHD_PASS_FILE="/var/ossec/etc/authd.pass"

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

log "Installing and Configuring Wazuh with Security"

# Step 1: Add Wazuh repository (same as original)
log "Adding Wazuh repository..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt stable main" | \
    tee /etc/apt/sources.list.d/wazuh.list
apt-get update

# Step 2: Install Wazuh Manager
log "Installing Wazuh Manager..."
apt-get install -y wazuh-manager

# Step 3: Install Filebeat
log "Installing Filebeat..."
apt-get install -y filebeat

# Step 4: Verify certificates exist
log "Verifying certificates..."
if [[ ! -f "${CERT_DIR}/wazuh/wazuh-cert.pem" ]]; then
    warn "Wazuh certificates not found. SSL configuration will be skipped."
    warn "Run generate_certs.sh first for full security setup."
    SKIP_SSL=true
else
    SKIP_SSL=false
fi

# Step 5: Create Wazuh certificate directory (if certificates exist)
if [[ "${SKIP_SSL}" == "false" ]]; then
    log "Setting up Wazuh certificate directory..."
    mkdir -p /var/ossec/etc/ssl
    cp "${CERT_DIR}/ca/ca-cert.pem" /var/ossec/etc/ssl/
    cp "${CERT_DIR}/wazuh/wazuh-cert.pem" /var/ossec/etc/ssl/
    cp "${CERT_DIR}/wazuh/wazuh-key.pem" /var/ossec/etc/ssl/

    # Set proper ownership
    chown -R "${WAZUH_USER}:${WAZUH_USER}" /var/ossec/etc/ssl
    chmod 750 /var/ossec/etc/ssl
    chmod 640 /var/ossec/etc/ssl/*

    log "Wazuh certificates configured"
fi

# Step 6: Generate Wazuh agent enrollment password
log "Generating secure agent enrollment password..."
WAZUH_AGENT_PASSWORD=$(openssl rand -base64 32)
echo "${WAZUH_AGENT_PASSWORD}" > "${AUTHD_PASS_FILE}"
chown "root:${WAZUH_USER}" "${AUTHD_PASS_FILE}"
chmod 640 "${AUTHD_PASS_FILE}"

log "Agent enrollment password saved to ${AUTHD_PASS_FILE}"

# Step 7: Configure Filebeat properly (FIXES THE CRITICAL ERROR)
log "Configuring Filebeat for Wazuh..."

# Create proper Filebeat configuration instead of copying logstash config to filebeat.yml
cat > /etc/filebeat/filebeat.yml << 'EOF'
###################### Filebeat Configuration for Wazuh #########################

# ============================== Filebeat inputs ===============================
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/ossec/logs/alerts/alerts.json
  fields:
    logtype: wazuh-alerts
  fields_under_root: true

# ============================== Filebeat modules ===============================
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

# ================================== General ===================================
name: wazuh-filebeat

# =================================== Kibana ===================================
setup.kibana:
  host: "https://localhost:5601"
  protocol: "https"
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/ssl/soc-certs/ca/ca-cert.pem"]
  ssl.verification_mode: certificate

# ------------------------------ Logstash Output -------------------------------
output.logstash:
  hosts: ["localhost:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/ssl/soc-certs/ca/ca-cert.pem"]
  ssl.certificate: "/etc/ssl/soc-certs/filebeat/filebeat-cert.pem"
  ssl.key: "/etc/ssl/soc-certs/filebeat/filebeat-key.pem"
  ssl.verification_mode: certificate

# ================================= Processors =================================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~

# ================================== Logging ===================================
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

EOF

# If no SSL certificates, create basic configuration
if [[ "${SKIP_SSL}" == "true" ]]; then
    log "Creating basic Filebeat configuration without SSL..."
    cat > /etc/filebeat/filebeat.yml << 'EOF'
###################### Filebeat Configuration for Wazuh (No SSL) #########################

filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/ossec/logs/alerts/alerts.json
  fields:
    logtype: wazuh-alerts
  fields_under_root: true

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

name: wazuh-filebeat

setup.kibana:
  host: "http://localhost:5601"

output.logstash:
  hosts: ["localhost:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF
fi

# Set proper ownership for Filebeat configuration
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

log "Filebeat configured for Wazuh log shipping"

# Step 8: Create basic Wazuh configuration
log "Creating Wazuh configuration..."

# Backup original config if it exists
if [[ -f "${WAZUH_CONFIG}" ]]; then
    cp "${WAZUH_CONFIG}" "${WAZUH_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Create enhanced Wazuh configuration
cat > "${WAZUH_CONFIG}" << 'EOF'
<!--
  Wazuh - Manager configuration
  More info at: https://documentation.wazuh.com
-->

<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <hostname>soc-wazuh-manager</hostname>
    <email_maxperhour>12</email_maxperhour>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
    <local_ip>0.0.0.0</local_ip>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
    
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
    
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    
    <ignore type="sregex">.log$|.swp$</ignore>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
  </syscheck>

  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.0.0.0/8</white_list>
    <white_list>172.16.0.0/12</white_list>
    <white_list>192.168.0.0/16</white_list>
  </global>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

</ossec_config>
EOF

# Add SSL configuration if certificates are available
if [[ "${SKIP_SSL}" == "false" ]]; then
    log "Adding SSL configuration to Wazuh..."
    
    # Add SSL settings to auth section
    sed -i '/<auth>/,/<\/auth>/{
        /<ssl_auto_negotiate>/a\
    <ssl_agent_ca>/var/ossec/etc/ssl/ca-cert.pem</ssl_agent_ca>\
    <ssl_manager_cert>/var/ossec/etc/ssl/wazuh-cert.pem</ssl_manager_cert>\
    <ssl_manager_key>/var/ossec/etc/ssl/wazuh-key.pem</ssl_manager_key>
    }' "${WAZUH_CONFIG}"
fi

# Set proper ownership
chown "${WAZUH_USER}:${WAZUH_USER}" "${WAZUH_CONFIG}"
chmod 640 "${WAZUH_CONFIG}"

log "Wazuh configuration created successfully"

# Step 9: Enable and start services
log "Enabling and starting Wazuh services..."
systemctl enable wazuh-manager filebeat
systemctl start wazuh-manager filebeat

# Wait for Wazuh to start
log "Waiting for Wazuh to start..."
for i in {1..30}; do
    if systemctl is-active --quiet wazuh-manager; then
        log "Wazuh manager started successfully"
        break
    fi
    if [[ $i -eq 30 ]]; then
        error "Wazuh manager failed to start within 30 seconds"
    fi
    sleep 2
done

# Step 10: Create agent enrollment test script
log "Creating agent enrollment script..."
cat > /usr/local/bin/test-agent-enrollment << EOF
#!/bin/bash
echo "Testing Wazuh agent enrollment process..."
echo "Agent enrollment password: \$(cat ${AUTHD_PASS_FILE})"
echo ""
echo "To enroll an agent, run on the agent machine:"
echo "echo '${WAZUH_AGENT_PASSWORD}' > /var/ossec/etc/authd.pass"
echo "chmod 640 /var/ossec/etc/authd.pass"
echo "chown root:wazuh /var/ossec/etc/authd.pass"
echo "/var/ossec/bin/agent-auth -m \$(hostname -I | awk '{print \$1}') -P '${WAZUH_AGENT_PASSWORD}'"
echo ""
echo "Then start the agent: systemctl start wazuh-agent"
EOF

chmod +x /usr/local/bin/test-agent-enrollment

log "Wazuh Manager and Filebeat installation completed successfully!"
echo
echo "==================================="
echo "WAZUH INSTALLATION SUMMARY"
echo "==================================="
echo
echo "✓ Wazuh Manager installed and configured"
echo "✓ Filebeat properly configured for log shipping"
echo "✓ Agent enrollment password generated"
if [[ "${SKIP_SSL}" == "false" ]]; then
    echo "✓ SSL/TLS certificates configured"
else
    echo "⚠ SSL/TLS not configured (certificates not found)"
fi
echo
echo "🔐 Agent enrollment password: ${AUTHD_PASS_FILE}"
echo "⚙️  Configuration file: ${WAZUH_CONFIG}"
echo "📋 Test agent enrollment: /usr/local/bin/test-agent-enrollment"
echo
echo "Service Ports:"
echo "- Agent enrollment (authd): 1515/tcp"
echo "- Agent communication: 1514/tcp"
echo
echo "Next Steps:"
echo "1. Configure agents using the enrollment password"
echo "2. Verify log shipping to ELK stack"
echo "3. Run configure_kibana.sh to setup Kibana dashboards"
echo
if [[ "${SKIP_SSL}" == "true" ]]; then
    warn "For full security, run generate_certs.sh and reconfigure with SSL"
fi
warn "Configure firewall rules to allow Wazuh ports (1514, 1515)"

log "Wazuh installation completed!"
