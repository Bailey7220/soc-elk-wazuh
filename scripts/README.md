# SOC ELK Wazuh Security Scripts

This directory contains security-enhanced installation and configuration scripts for the SOC ELK Wazuh stack.

## 🚀 Scripts Overview

### Core Security Scripts
- **`generate_certs.sh`** - Generates SSL/TLS certificates for all services
- **`install_elk.sh`** - Installs ELK stack with X-Pack security
- **`install_wazuh.sh`** - Installs Wazuh with SSL/TLS and authentication  
- **`configure_kibana.sh`** - ⚠️ **NEEDS UPDATE** - Currently basic version
- **`configure_kibana_secure.sh`** - ✅ **NEW** - Enhanced version with security
- **`deploy_soc_security.sh`** - ✅ **NEW** - Master deployment script

## 🔧 Quick Implementation Steps

### Option 1: Complete Deployment (Recommended)
```bash
# First, update configure_kibana.sh with secure version
sudo ./deploy_soc_security.sh
```

### Option 2: Step-by-Step Deployment
```bash
# 1. Generate certificates
sudo ./generate_certs.sh

# 2. Install ELK with security
sudo ./install_elk.sh

# 3. Install Wazuh with security
sudo ./install_wazuh.sh

# 4. Configure Kibana (use secure version)
sudo ./configure_kibana_secure.sh
```

## 🔒 Security Features Implemented

- **SSL/TLS Encryption**: All inter-service communication encrypted
- **X-Pack Security**: Authentication and authorization for Elasticsearch  
- **Password Authentication**: Secure Wazuh agent enrollment
- **Certificate Management**: Complete PKI infrastructure with 10-year validity
- **Audit Logging**: Comprehensive security event logging
- **Role-Based Access**: SOC admin, analyst, and viewer roles

## 🎯 Post-Deployment

1. **Access Kibana**: `https://your-server-ip:5601`
2. **Login**: Use `elastic` user (password in `/etc/elasticsearch/passwords.txt`)
3. **Configure Agents**: Use `/usr/local/bin/test-agent-enrollment`
4. **Health Check**: Run `/usr/local/bin/soc-health-check`
5. **Set up Dashboards**: Configure Wazuh visualizations and alerts

## 🚨 Critical Security Warnings

⚠️ **Change all default passwords immediately after deployment**
⚠️ **Secure the passwords file**: `/etc/elasticsearch/passwords.txt`
⚠️ **Configure firewall rules** for ports 5601, 9200, 1514, 1515
⚠️ **Set up regular certificate monitoring** (10-year expiration)
⚠️ **Implement network segmentation** for production environments

## 🛠️ System Management

### Health Monitoring
```bash
# Check all services
sudo /usr/local/bin/soc-health-check

# Individual service status
systemctl status elasticsearch kibana wazuh-manager filebeat
```

### Log Monitoring  
```bash
# View service logs
journalctl -u elasticsearch -f
journalctl -u kibana -f
journalctl -u wazuh-manager -f
```

### Certificate Management
```bash
# Verify certificates
openssl x509 -in /etc/ssl/soc-certs/ca/ca-cert.pem -text -noout

# Check expiration
openssl x509 -in /etc/ssl/soc-certs/ca/ca-cert.pem -checkend 86400 -noout
```

## 📁 Important File Locations

| Component | Configuration | Certificates | Logs |
|-----------|---------------|--------------|------|
| Elasticsearch | `/etc/elasticsearch/elasticsearch.yml` | `/etc/elasticsearch/certs/` | `/var/log/elasticsearch/` |
| Kibana | `/etc/kibana/kibana.yml` | `/etc/kibana/certs/` | `/var/log/kibana/` |
| Wazuh | `/var/ossec/etc/ossec.conf` | `/var/ossec/etc/ssl/` | `/var/ossec/logs/` |
| Filebeat | `/etc/filebeat/filebeat.yml` | `/etc/ssl/soc-certs/filebeat/` | `/var/log/filebeat/` |

## 🔑 Default Credentials

- **Elasticsearch Admin**: `elastic` / `[see /etc/elasticsearch/passwords.txt]`
- **Kibana System**: `kibana_system` / `[see /etc/elasticsearch/passwords.txt]`
- **Wazuh Agent Enrollment**: `[see /var/ossec/etc/authd.pass]`

## 🚀 Career Impact

This implementation demonstrates:
- **Enterprise Security Architecture** - Complete SSL/TLS PKI infrastructure
- **Compliance Readiness** - Audit logging and access controls
- **Production Operations** - Monitoring, health checks, and automation
- **Security Engineering** - Defense in depth with multiple security layers
- **SOC Management** - Role-based access for different analyst levels

Perfect for showcasing **Senior SOC Analyst** and **Security Engineer** capabilities to potential employers.
