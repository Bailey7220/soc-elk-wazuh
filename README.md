Table of Contents

    Overview

    Architecture

    Prerequisites

    Setup Guide

        1. Provision VM

        2. System Hardening

        3. Install ELK Stack

        4. Install Wazuh Manager

        5. Deploy Wazuh Agent

        6. Configure Dashboards & Alerts

    Testing & Validation

    Automation (Optional)

    Next Steps

    License

Overview

In modern security operations, having real-time visibility into system logs and endpoint activity is essential. This project illustrates how to:

    Launch a free-tier VM.

    Harden the system and firewall.

    Deploy Elasticsearch, Logstash, and Kibana for log aggregation and visualization.

    Integrate Wazuh for host-based intrusion detection, file integrity monitoring, and rootkit checks.

    Build custom dashboards and alerting rules to surface high-priority security events.

All configuration and deployment steps are scripted for repeatability.

Architecture

+-----------------+        Beats         +-------------+
|  Wazuh Agent    | ----> Filebeat ---> |  Logstash   |
|  (Endpoint VM)  |                    +-------------+
+-----------------+                           |
                                              | Elasticsearch Index
                 +-----------------+          v
                 |  Wazuh Manager  |------> +-------------+
                 +-----------------+        | Elasticsearch|
                                              +-------------+
                                                 |
                                                 v
                                             +--------+
                                             | Kibana |
                                             +--------+

Prerequisites

    Cloud Account: AWS Free Tier, Google Cloud, or Oracle Cloud

    VM Specs: ≥1 vCPU, 1 GB RAM, Ubuntu 20.04 LTS

    SSH Key Pair: For secure access

    Local Tools: Git, SSH client, (optional) Terraform or Ansible


Setup Guide
1. Provision VM

    Sign into your cloud provider.

    Launch a Ubuntu 20.04 VM (1 vCPU, 1 GB RAM).

    Create a security group allowing:

        SSH (22) → your IP

        Kibana (5601) → your IP

        Logstash Beats (5044) → localhost/Wazuh subnet

    Attach your SSH key and note the public IP.

2. System Hardening

sudo apt update && sudo apt upgrade -y  
sudo adduser socadmin && usermod -aG sudo socadmin  
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config  
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config  
sudo systemctl restart sshd  
sudo apt install ufw fail2ban -y  
sudo ufw default deny incoming  
sudo ufw default allow outgoing  
sudo ufw allow OpenSSH  
sudo ufw allow from YOUR_IP to any port 5601  
sudo ufw allow from 127.0.0.1 to any port 5044  
sudo ufw enable  

3. Install ELK Stack
Add Elastic Repository

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -  
sudo apt install apt-transport-https -y  
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list  
sudo apt update  

Elasticsearch

sudo apt install elasticsearch -y  
sudo systemctl enable --now elasticsearch  



    Config: in /etc/elasticsearch/elasticsearch.yml, set network.host: localhost.

Logstash

sudo apt install logstash -y  



    Pipeline: add configs/logstash/wazuh.conf for Filebeat input and Wazuh alerts.

Kibana

sudo apt install kibana -y  
sudo systemctl enable --now kibana  



    Config: in /etc/kibana/kibana.yml, set server.host: "0.0.0.0" (or use SSH tunnel).

4. Install Wazuh Manager

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -  
echo "deb https://packages.wazuh.com/4.x/apt stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list  
sudo apt update  
sudo apt install wazuh-manager -y  



    Integration: configure Wazuh to forward alerts to Elasticsearch via Logstash.

5. Deploy Wazuh Agent

On a separate VM or container:
sudo apt install wazuh-agent -y  
/var/ossec/bin/agent-auth -m MANAGER_IP  
sudo systemctl enable --now wazuh-agent  

Verify agent logs in Kibana under the Wazuh app.
6. Configure Dashboards & Alerts

    Install the Wazuh Kibana plugin.

    Import built-in dashboards, then customize:

        Host Overview: CPU, memory, file integrity.

        Alerts: severity levels, rule categories.

    Set up Watcher or ElastAlert to email critical alerts.

Testing & Validation

    Generate Test Events:

        SSH brute-force with hydra or deliberate file changes in monitored directories.

    Verify Detection:

        Confirm alerts appear in Kibana.

        Capture screenshots in diagrams/.

    Document Findings:

        Include sample alert JSON and investigation notes in testing/.

Automation (Optional)

    Terraform: terraform/main.tf provisions the VM, network, and firewall.

    Ansible: ansible/playbook.yml installs and configures all components.

Next Steps

    Integrate Suricata for network IDS.

    Add Grafana for alternate dashboards.

    Implement centralized alert management (PagerDuty/Slack).

License

This project is licensed under the Apache 2.0 License.
Feel free to reuse, modify, and extend for your own learning or professional portfolio.
