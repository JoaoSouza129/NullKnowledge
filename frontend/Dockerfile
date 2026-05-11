FROM nginx:1.27-alpine

# Assets estáticos
COPY index.html view.html crypto.js script.js /usr/share/nginx/html/

# Template processado por envsubst no arranque
COPY nginx.conf /etc/nginx/templates/default.conf

# Defaults (sobrepostos pelo Compose/K8s)
ENV BACKEND_HOST=backend \
    BACKEND_PORT=5050 \
    NGINX_ENVSUBST_FILTER=^(BACKEND_HOST|BACKEND_PORT)$

EXPOSE 80
# CMD herdado da imagem base (nginx -g "daemon off;")