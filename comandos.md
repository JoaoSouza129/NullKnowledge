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


# Push com rebase
git pull --rebase origin main
git push origin main

# Comandos pods
export KUBECONFIG=~/.kube/config-amnesia
kubectl get pods -n amnesia-shh -w

# Comandos VM da Google

sudo apt-get install -y nmap nikto

# 1. Headers de segurança
curl -I https://amnesia-shh.duckdns.org

# 2. Tentar acesso a ficheiros ocultos
curl -s -o /dev/null -w "%{http_code}" https://amnesia-shh.duckdns.org/.env
curl -s -o /dev/null -w "%{http_code}" https://amnesia-shh.duckdns.org/.git/config

# 3. Tentar path traversal
curl -s -o /dev/null -w "%{http_code}" https://amnesia-shh.duckdns.org/../etc/passwd

# 4. Tentar acesso direto ao Redis
curl -v telnet://amnesia-shh.duckdns.org:6379

# 5. Força bruta de IDs
for i in $(seq 1 5); do
  ID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 12)
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://amnesia-shh.duckdns.org/api/secrets/$ID)
  echo "ID: $ID → HTTP $STATUS"
done