provider "aws" {
  region = "us-east-1"
}

resource "aws_key_pair" "soc_key" {
  key_name   = "soc-project-key"
  public_key = file("${path.module}/public_key.pub")
}

resource "aws_security_group" "soc_sg" {
  name        = "soc-project-sg"
  description = "Allow SSH, Kibana, Logstash Beats"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  ingress {
    description = "Kibana"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  ingress {
    description = "Logstash Beats"
    from_port   = 5044
    to_port     = 5044
    protocol    = "tcp"
    cidr_blocks = ["127.0.0.1/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "soc_vm" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.soc_key.key_name
  vpc_security_group_ids = [aws_security_group.soc_sg.id]

  tags = {
    Name = "soc-elk-wazuh"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
}

output "public_ip" {
  value = aws_instance.soc_vm.public_ip
}
