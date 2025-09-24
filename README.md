#SOC ELK Wazuh Deployment#

This repository provides an automated setup for a security operations center (SOC) stack using the ELK (Elasticsearch, Logstash, Kibana) stack and Wazuh. It includes scripts, Ansible playbooks, and CI workflows to install, configure, and validate each component.



    Git 2.25+

    Bash shell on Linux or WSL for Windows

    A Linux target server (Ubuntu 20.04+) with SSH access

    Cloud credentials (if using Terraform to provision hosts)

Quick Start

    Clone the repository
   
    git clone https://github.com/your-org/soc-elk-wazuh.git
    cd soc-elk-wazuh


Review and customize configuration files in configs/.

    elasticsearch.yml: cluster name, network settings, paths

    kibana.yml: Kibana host, port, SSL settings

    logstash/wazuh.conf: pipeline for ingesting Wazuh alerts

Provision infrastructure (optional)

cd terraform
terraform init
terraform plan
terraform apply

Run installation scripts on your target host(s)

# On the target machine:
sudo bash scripts/install_elk.sh
sudo bash scripts/install_wazuh.sh
sudo bash scripts/configure_kibana.sh

Apply Ansible playbook (alternative to scripts)

ansible-playbook -i inventory ansible/playbook.yml


Access the stack

    Elasticsearch: http://<host>:9200

    Kibana: http://<host>:5601

CI Pipeline

The CI workflow (.github/workflows/ci.yml) runs on every push and pull request:

    ShellCheck
    Lints all scripts/*.sh for style and errors.

    YAMLLint
    Finds and validates elasticsearch.yml for strict YAML conformance.

    Terraform

        terraform init -backend=false

        terraform fmt -check

        terraform validate

    Ansible Lint

        Installs ansible-core and ansible-lint via pip

        Installs required collections (community.general, ansible.posix)

        Lints ansible/playbook.yml for best practices

All checks must pass before merging changes.
Troubleshooting

    ShellCheck errors: Ensure scripts use LF line endings (dos2unix scripts/*.sh).

    YAMLLint errors: Verify configs/elasticsearch.yml is in configs/ and uses LF endings.

    Terraform errors: Always run terraform init -backend=false before validate.

    Ansible lint errors: Install and reference collections explicitly; use fully-qualified module names.

Next Steps

    Customize dashboards in Kibana for Wazuh alerts.

    Secure the stack with SSL, authentication, and firewalls.

    Automate backups for Elasticsearch indices.

    Extend logging pipelines (e.g., Filebeat modules, custom grok patterns).
