variable "my_ip" {
  description = "Your IP in CIDR (68.229.244.149/32)"
  type        = string
}

variable "public_key_path" {
  description = "Absolute path to your SSH public key"
  type        = string
  default     = "/c/Users/OKCMV/.ssh/id_ed25519.pub"
}
