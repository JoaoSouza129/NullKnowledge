# 🔒 Amnesia Shh

Plataforma web para partilha segura de segredos temporários com arquitetura Zero-Knowledge.
O servidor nunca tem acesso ao conteúdo em claro — toda a encriptação ocorre exclusivamente no browser.

🌐 **Demo:** https://amnesia-shh.duckdns.org

---

## Funcionalidades

- Encriptação AES-256-GCM no browser com Web Crypto API nativa
- Chave de desencriptação no fragmento `#` da URL — nunca enviada ao servidor
- Expiração automática por TTL (1 hora, 1 dia ou 7 dias)
- Destruição do segredo após primeira leitura (leitura única)
- Arquitetura Zero-Knowledge — servidor armazena apenas blobs encriptados
- Pipeline CI/CD completa com GitHub Actions e ArgoCD
- Deploy em Kubernetes (k3s) com TLS automático via Let's Encrypt

---

## Arquitetura
Browser (Zero-Knowledge)
│
│ HTTPS
▼
Ingress — Traefik
│
├── /* ──────▶ Frontend (nginx) — ficheiros estáticos
└── /api/* ──▶ Backend (Flask + Gunicorn) ──▶ Redis (TTL)

### Stack

| Camada | Tecnologia |
|---|---|
| Frontend | HTML + JavaScript + Tailwind CSS |
| Criptografia | Web Crypto API — AES-256-GCM |
| Backend | Python 3.11 + Flask + Gunicorn |
| Base de dados | Redis 7.4 |
| Contentorização | Docker + Docker Compose |
| Orquestração | Kubernetes — k3s |
| CI/CD | GitHub Actions + ArgoCD |
| Infraestrutura | Terraform |
| TLS | cert-manager + Let's Encrypt |
| Registry | GitHub Container Registry (ghcr.io) |

---

## Estrutura do Repositório
.
├── backend/
│   ├── app.py              # API Flask — Zero-Knowledge
│   ├── requirements.txt
│   └── Dockerfile          # Multi-stage build
├── frontend/
│   ├── index.html          # Página de criação de segredo
│   ├── view.html           # Página de leitura de segredo
│   ├── crypto.js           # AES-256-GCM — Web Crypto API
│   ├── script.js           # Lógica de criação
│   ├── nginx.conf          # Reverse proxy + security headers
│   └── Dockerfile          # nginx:alpine
├── k8s/
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── ingress.yaml
│   ├── argocd-app.yaml
│   ├── redis/
│   │   ├── statefulset.yaml
│   │   └── service.yaml
│   ├── backend/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   └── frontend/
│       ├── deployment.yaml
│       └── service.yaml
├── terraform/
│   ├── main.tf             # Provisionamento via SSH
│   ├── variables.tf
│   ├── outputs.tf
│   ├── versions.tf
│   └── install-k3s.sh      # Instala k3s, cert-manager e ArgoCD
├── docker-compose.yml      # Execução local
└── README.md

---

## Execução Local — Docker Compose

### Pré-requisitos

- Docker
- Docker Compose

### Passos

```bash
# 1. Clona o repositório
git clone https://github.com/JoaoSouza129/NullKnowledge.git
cd NullKnowledge

# 2. Cria o ficheiro de variáveis de ambiente
echo "REDIS_PASSWORD=password_local" > .env

# 3. Arranca os serviços
docker compose up -d

# 4. Abre no browser
open http://localhost
```

### Verificar estado dos serviços

```bash
docker compose ps
docker compose logs -f
```

### Parar os serviços

```bash
docker compose down
```

---

## Deploy em Kubernetes

### Pré-requisitos

- Terraform >= 1.6
- kubectl
- Acesso SSH à Droplet
- Conta GitHub com repositório público

### Passo 1 — Provisionar o cluster com Terraform

```bash
cd terraform

# Cria o ficheiro de variáveis (não commitar)
cat > terraform.tfvars <<EOF
droplet_ip           = "IP_DA_DROPLET"
ssh_private_key_path = "~/.ssh/id_ed25519"
ssh_user             = "root"
EOF

# Inicializa e aplica
terraform init
terraform apply -var-file="terraform.tfvars"
```

### Passo 2 — Configurar o kubeconfig

```bash
mkdir -p ~/.kube
scp root@IP_DA_DROPLET:/etc/rancher/k3s/k3s.yaml ~/.kube/config-amnesia
sed -i '' 's/127.0.0.1/IP_DA_DROPLET/g' ~/.kube/config-amnesia
export KUBECONFIG=~/.kube/config-amnesia

# Verificar cluster
kubectl get nodes
kubectl get pods -n argocd
```

### Passo 3 — Aplicar o ArgoCD Application

```bash
kubectl apply -f k8s/argocd-app.yaml
```

O ArgoCD passa a gerir todos os recursos automaticamente a partir da pasta `/k8s`.

### Passo 4 — Aceder à UI do ArgoCD

```bash
export KUBECONFIG=~/.kube/config-amnesia
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

Abre `https://localhost:8080` — utilizador `admin`.

Password inicial:
```bash
kubectl get secret argocd-initial-admin-secret -n argocd \
  -o jsonpath="{.data.password}" | base64 -d && echo
```

---

## Pipeline CI/CD

Cada push para a branch `main` desencadeia automaticamente:
git push origin main
│
▼
CI — Build & Push
└── Constrói e publica imagens no ghcr.io com tag sha-xxxxxxx
│
▼
CD — Update Manifests
└── Atualiza tags nos manifestos k8s/ e faz commit
│
▼
ArgoCD
└── Deteta alteração e sincroniza o cluster automaticamente

---

## Segurança

### Modelo Zero-Knowledge

| Componente | O que o servidor sabe |
|---|---|
| Conteúdo do segredo | Nunca — só blobs cifrados |
| Chave de cifragem | Nunca — fica no fragmento `#` da URL |
| Plaintext | Nunca — cifragem ocorre no browser |

### Medidas implementadas

- AES-256-GCM com IV aleatório por cifragem
- Chave gerada com `window.crypto.getRandomValues()` — CSPRNG do SO
- HTTPS obrigatório — TLS via cert-manager + Let's Encrypt
- Headers HTTP — CSP, X-Frame-Options, Referrer-Policy, Cache-Control
- Utilizador não-root nos contentores Docker
- Redis sem porta pública — só acessível internamente
- Operação atómica `GETDEL` para leitura única sem race conditions
- Logs sem exposição de conteúdo dos segredos

---

## Variáveis de Ambiente

### Backend

| Variável | Padrão | Descrição |
|---|---|---|
| `REDIS_HOST` | `localhost` | Endereço do Redis |
| `REDIS_PORT` | `6379` | Porta do Redis |
| `REDIS_PASSWORD` | `None` | Password do Redis |
| `MAX_SECRET_BYTES` | `10000` | Tamanho máximo do segredo |
| `MAX_TTL_SECONDS` | `604800` | TTL máximo em segundos |
| `ALLOWED_ORIGIN` | `*` | Origem permitida para CORS |
| `LOG_LEVEL` | `INFO` | Nível de logging |

### Frontend

| Variável | Padrão | Descrição |
|---|---|---|
| `BACKEND_HOST` | `backend` | Endereço do backend |
| `BACKEND_PORT` | `5050` | Porta do backend |

---

## Unidade Curricular

Trabalho 2 — Computação Distribuída
Curso: Engenharia Informática
