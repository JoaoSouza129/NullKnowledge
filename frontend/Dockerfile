FROM nginx:1.27-alpine

COPY index.html view.html crypto.js script.js logo.png /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/nginx.conf.template

ENV BACKEND_HOST=backend \
    BACKEND_PORT=5050

EXPOSE 80

# Substitui APENAS ${BACKEND_HOST} e ${BACKEND_PORT}, preservando $host, $uri, etc.
CMD ["/bin/sh", "-c", \
    "envsubst '${BACKEND_HOST} ${BACKEND_PORT}' < /etc/nginx/nginx.conf.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"]