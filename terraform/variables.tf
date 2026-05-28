variable "droplet_ip" {
  description = "IP público da Droplet Digital Ocean"
  type        = string
}

variable "ssh_private_key_path" {
  description = "Caminho para a chave SSH privada local"
  type        = string
  default     = "~/.ssh/id_rsa"
}

variable "ssh_user" {
  description = "Utilizador SSH da Droplet"
  type        = string
  default     = "root"
}