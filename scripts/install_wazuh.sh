#!/usr/bin/env bash
set -e

# 1. Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update

# 2. Install Wazuh Manager & API
apt-get install -y wazuh-manager

# 3. Install Filebeat (for Wazuh integration)
apt-get install -y filebeat
cp ../configs/logstash/wazuh.conf /etc/filebeat/filebeat.yml

# 4. Enable and start services
systemctl enable wazuh-manager filebeat
systemctl start wazuh-manager filebeat

echo "Wazuh Manager and Filebeat installed."
