FROM nginx:1.27-alpine

# Assets estáticos
COPY index.html view.html crypto.js script.js logo.png /usr/share/nginx/html/

# CORREÇÃO: Adicionada a extensão .template obrigatória para o Docker ativar o envsubst
COPY nginx.conf /etc/nginx/templates/default.conf.template

# Defaults (sobrepostos pelo Compose/K8s)
ENV BACKEND_HOST=backend \
    BACKEND_PORT=5050 \
    NGINX_ENVSUBST_FILTER=^(BACKEND_HOST|BACKEND_PORT)$

EXPOSE 80
# CMD herdado da imagem base (nginx -g "daemon off;")