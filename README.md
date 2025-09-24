# soc-elk-wazuh

**Centralized Logging & Endpoint Detection for SOC Monitoring**

This repository contains automated scripts and configurations to deploy:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Wazuh Manager & Agent

on a free-tier Ubuntu cloud VM. Follow each script in order once you SSH into the target VM.

## Table of Contents

- [Prerequisites](#prerequisites)  
- [Scripts Overview](#scripts-overview)  
- [Execution Order](#execution-order)  
- [Directory Structure](#directory-structure)  
- [Next Steps](#next-steps)  
- [License](#license)

## Prerequisites

- Ubuntu 20.04 LTS VM (≥1 vCPU, 1 GB RAM)  
- SSH access with `sudo` privileges  
- Git and network connectivity to internet

## Scripts Overview

1. **install_elk.sh**  
   Adds Elastic’s repo, installs and configures Elasticsearch, Logstash, and Kibana.

2. **install_wazuh.sh**  
   Adds Wazuh’s repo, installs and configures the Wazuh Manager and Filebeat.

3. **configure_kibana.sh**  
   Installs the Wazuh Kibana plugin, creates index patterns, and imports dashboards.

## Execution Order

On your VM:

cd ~/soc-elk-wazuh/scripts
sudo bash install_elk.sh
sudo bash install_wazuh.sh
sudo bash configure_kibana.sh


## Directory Structure

soc-elk-wazuh/
├── README.md
├── LICENSE
├── diagrams/
├── terraform/
├── ansible/
├── scripts/
│ ├── install_elk.sh
│ ├── install_wazuh.sh
│ └── configure_kibana.sh
└── configs/
├── elasticsearch.yml
├── kibana.yml
└── logstash/
└── wazuh.conf


## Next Steps

- Simulate threat logs and validate detection in Kibana.  
- Automate VM provisioning with Terraform or Ansible.  
- Extend with Suricata network IDS or custom alerting rules.

## License

Apache 2.0 License
