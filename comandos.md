ssh root@159.89.20.141

# Nginx Proxy Manager
http://159.89.20.141:81

# Port-forward ao Argo CD
kubectl port-forward svc/argocd-server -n argocd 8080:443       

# MOSTRAR DB NA VM
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
REDIS_PWD=$(kubectl get secret amnesia-secret -n amnesia-shh -o jsonpath='{.data.REDIS_PASSWORD}' | base64 -d)
kubectl exec -n amnesia-shh -it redis-0 -- redis-cli -a $REDIS_PWD

# MOSTRAR DB LOCAL
export KUBECONFIG=~/.kube/config-amnesia
REDIS_PWD=$(kubectl get secret amnesia-secret -n amnesia-shh -o jsonpath='{.data.REDIS_PASSWORD}' | base64 -d)
kubectl exec -n amnesia-shh -it redis-0 -- redis-cli -a $REDIS_PWD