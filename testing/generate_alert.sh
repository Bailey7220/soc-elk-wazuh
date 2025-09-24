#!/usr/bin/env bash
# Generate a dummy Wazuh alert to Elasticsearch
ES_URL="http://localhost:9200/wazuh-alerts-$(date +'%Y.%m.%d')/_doc"
curl -s -XPOST "$ES_URL" -H 'Content-Type: application/json' \
  -d '{
    "@timestamp":"'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",
    "rule": {"level":7,"description":"Test Alert"},
    "agent":{"id":"001","name":"test-agent"},
    "decoder":{"name":"test-decoder"},
    "manager":{"name":"test-manager"},
    "data":{"test":"value"}
  }'
