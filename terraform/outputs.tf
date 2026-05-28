output "kubeconfig_command" {
  description = "Comando para copiar o kubeconfig da Droplet"
  value       = "scp ${var.ssh_user}@${var.droplet_ip}:/etc/rancher/k3s/k3s.yaml ~/.kube/config-amnesia && sed -i 's/127.0.0.1/${var.droplet_ip}/g' ~/.kube/config-amnesia"
}

output "argocd_url" {
  description = "URL do ArgoCD (acesso via port-forward)"
  value       = "kubectl port-forward svc/argocd-server -n argocd 8080:443 --kubeconfig ~/.kube/config-amnesia"
}