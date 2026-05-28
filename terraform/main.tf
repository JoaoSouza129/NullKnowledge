resource "null_resource" "k3s_setup" {
   connection {
     type        = "ssh"
     host        = var.droplet_ip
     user        = var.ssh_user
     agent       = true
     timeout     = "5m"
  }

  provisioner "file" {
    source      = "${path.module}/install-k3s.sh"
    destination = "/tmp/install-k3s.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/install-k3s.sh",
      "/tmp/install-k3s.sh"
    ]
  }
}