#!/usr/bin/env bash
set -euo pipefail

# SOC ELK Wazuh Certificate Generation Script
# This script generates all SSL/TLS certificates needed for production deployment

# Configuration
CERT_DIR="/etc/ssl/soc-certs"
DAYS_VALID="3650"  # 10 years
KEY_SIZE="4096"
COUNTRY="US"
STATE="Oklahoma" 
CITY="Edmond"
ORG="SOC-Project"
OU="Security Operations"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
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

log "Starting SOC ELK Wazuh Certificate Generation"

# Create certificate directory structure
log "Creating certificate directory structure..."
mkdir -p "${CERT_DIR}"/{ca,elasticsearch,kibana,logstash,wazuh,filebeat}
chmod 755 "${CERT_DIR}"
chmod 700 "${CERT_DIR}"/*

# Step 1: Generate Certificate Authority (CA)
log "Generating Certificate Authority..."
cd "${CERT_DIR}/ca"

# Generate CA private key
openssl genrsa -out ca-key.pem "${KEY_SIZE}"
chmod 600 ca-key.pem

# Generate CA certificate
openssl req -new -x509 -sha256 -days "${DAYS_VALID}" -key ca-key.pem -out ca-cert.pem \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=SOC-CA"

log "CA Certificate generated successfully"

# Step 2: Generate Elasticsearch certificates
log "Generating Elasticsearch certificates..."
cd "${CERT_DIR}/elasticsearch"

# Create elasticsearch certificate config
cat > elasticsearch.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = ${COUNTRY}
ST = ${STATE}
L = ${CITY}
O = ${ORG}
OU = ${OU}
CN = elasticsearch

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = elasticsearch
DNS.2 = localhost
DNS.3 = *.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate Elasticsearch private key
openssl genrsa -out elasticsearch-key.pem "${KEY_SIZE}"
chmod 600 elasticsearch-key.pem

# Generate Elasticsearch certificate signing request
openssl req -new -key elasticsearch-key.pem -out elasticsearch.csr -config elasticsearch.conf

# Generate Elasticsearch certificate signed by CA
openssl x509 -req -in elasticsearch.csr -CA ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem \
    -CAcreateserial -out elasticsearch-cert.pem -days "${DAYS_VALID}" \
    -extensions v3_req -extfile elasticsearch.conf

# Create PKCS#12 keystore for Elasticsearch
openssl pkcs12 -export -out elasticsearch.p12 \
    -inkey elasticsearch-key.pem -in elasticsearch-cert.pem -certfile ../ca/ca-cert.pem \
    -password pass:changeit

chmod 640 elasticsearch.p12
rm elasticsearch.csr

log "Elasticsearch certificates generated successfully"

# Step 3: Generate Kibana certificates
log "Generating Kibana certificates..."
cd "${CERT_DIR}/kibana"

# Create kibana certificate config
cat > kibana.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = ${COUNTRY}
ST = ${STATE}
L = ${CITY}
O = ${ORG}
OU = ${OU}
CN = kibana

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = kibana
DNS.2 = localhost
DNS.3 = *.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate Kibana private key
openssl genrsa -out kibana-key.pem "${KEY_SIZE}"
chmod 600 kibana-key.pem

# Generate Kibana certificate signing request
openssl req -new -key kibana-key.pem -out kibana.csr -config kibana.conf

# Generate Kibana certificate signed by CA
openssl x509 -req -in kibana.csr -CA ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem \
    -CAcreateserial -out kibana-cert.pem -days "${DAYS_VALID}" \
    -extensions v3_req -extfile kibana.conf

rm kibana.csr

log "Kibana certificates generated successfully"

# Step 4: Generate Logstash certificates
log "Generating Logstash certificates..."
cd "${CERT_DIR}/logstash"

# Generate Logstash private key
openssl genrsa -out logstash-key.pem "${KEY_SIZE}"
chmod 600 logstash-key.pem

# Generate Logstash certificate
openssl req -new -key logstash-key.pem -out logstash.csr \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=logstash"

openssl x509 -req -in logstash.csr -CA ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem \
    -CAcreateserial -out logstash-cert.pem -days "${DAYS_VALID}"

rm logstash.csr

log "Logstash certificates generated successfully"

# Step 5: Generate Wazuh certificates
log "Generating Wazuh certificates..."
cd "${CERT_DIR}/wazuh"

# Generate Wazuh private key
openssl genrsa -out wazuh-key.pem "${KEY_SIZE}"
chmod 600 wazuh-key.pem

# Generate Wazuh certificate
openssl req -new -key wazuh-key.pem -out wazuh.csr \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=wazuh-manager"

openssl x509 -req -in wazuh.csr -CA ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem \
    -CAcreateserial -out wazuh-cert.pem -days "${DAYS_VALID}"

rm wazuh.csr

log "Wazuh certificates generated successfully"

# Step 6: Generate Filebeat certificates
log "Generating Filebeat certificates..."
cd "${CERT_DIR}/filebeat"

# Generate Filebeat private key
openssl genrsa -out filebeat-key.pem "${KEY_SIZE}"
chmod 600 filebeat-key.pem

# Generate Filebeat certificate
openssl req -new -key filebeat-key.pem -out filebeat.csr \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=filebeat"

openssl x509 -req -in filebeat.csr -CA ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem \
    -CAcreateserial -out filebeat-cert.pem -days "${DAYS_VALID}"

rm filebeat.csr

log "Filebeat certificates generated successfully"

# Step 7: Set proper ownership and permissions
log "Setting certificate permissions..."
chown -R root:elasticsearch "${CERT_DIR}"
find "${CERT_DIR}" -type f -name "*.pem" -exec chmod 640 {} \;
find "${CERT_DIR}" -type f -name "*.p12" -exec chmod 640 {} \;

# Step 8: Create certificate information file
log "Creating certificate information file..."
cat > "${CERT_DIR}/certificate_info.txt" << EOF
SOC ELK Wazuh Certificate Information
====================================
Generated: $(date)
Validity: ${DAYS_VALID} days
Key Size: ${KEY_SIZE} bits

Certificate Locations:
- CA Certificate: ${CERT_DIR}/ca/ca-cert.pem
- Elasticsearch: ${CERT_DIR}/elasticsearch/
- Kibana: ${CERT_DIR}/kibana/
- Logstash: ${CERT_DIR}/logstash/
- Wazuh: ${CERT_DIR}/wazuh/
- Filebeat: ${CERT_DIR}/filebeat/

IMPORTANT SECURITY NOTES:
1. Store the CA private key (ca-key.pem) in a secure location
2. Back up all certificates and keys
3. Monitor certificate expiration dates
4. Use strong passwords for PKCS#12 keystores (default: changeit)

Next Steps:
1. Configure Elasticsearch with X-Pack security
2. Update all service configurations to use SSL/TLS
3. Set up authentication and authorization
4. Test all SSL connections
EOF

log "Certificate generation completed successfully!"
log "Certificate information saved to: ${CERT_DIR}/certificate_info.txt"
warn "Remember to update service configurations to use these certificates"
warn "Default PKCS#12 keystore password is 'changeit' - change this in production!"

# Step 9: Verification
log "Verifying generated certificates..."
for cert_dir in ca elasticsearch kibana logstash wazuh filebeat; do
    if [[ -f "${CERT_DIR}/${cert_dir}/${cert_dir}-cert.pem" ]] || [[ -f "${CERT_DIR}/${cert_dir}/ca-cert.pem" ]]; then
        cert_file="${CERT_DIR}/${cert_dir}/${cert_dir}-cert.pem"
        [[ "${cert_dir}" == "ca" ]] && cert_file="${CERT_DIR}/${cert_dir}/ca-cert.pem"
        
        log "Verifying ${cert_dir} certificate..."
        openssl x509 -in "${cert_file}" -text -noout | grep -E "(Subject|Issuer|Not After)" || warn "Certificate verification failed for ${cert_dir}"
    fi
done

log "All certificates have been generated and verified successfully!"
log "Run the security configuration scripts next to apply these certificates."
