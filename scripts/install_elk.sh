#!/usr/bin/env bash
set -e

# 1. Add Elastic APT repo
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
apt-get update
apt-get install -y apt-transport-https
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" \
  > /etc/apt/sources.list.d/elastic-7.x.list
apt-get update

# 2. Install Elasticsearch
apt-get install -y elasticsearch
cp ../configs/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml
systemctl enable elasticsearch
systemctl start elasticsearch

# 3. Install Logstash
apt-get install -y logstash
cp ../configs/logstash/wazuh.conf /etc/logstash/conf.d/02-wazuh.conf
systemctl enable logstash
systemctl start logstash

# 4. Install Kibana
apt-get install -y kibana
cp ../configs/kibana.yml /etc/kibana/kibana.yml
systemctl enable kibana
systemctl start kibana

echo "ELK Stack installed and running."
