#!/usr/bin/env bash
set -e

# Install Wazuh Kibana plugin
/usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh-kibana-4.x.x.zip

# Restart Kibana to load plugin
systemctl restart kibana

# Create index pattern via Kibana API (requires no auth by default)
curl -XPOST "http://localhost:5601/api/saved_objects/index-pattern/wazuh-alerts-*" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{ "attributes": { "title": "wazuh-alerts-*", "timeFieldName": "@timestamp" } }'

echo "Kibana configured with Wazuh plugin and index pattern."
