FROM nginx:1.27-alpine

# Copia explicitamente os HTMLs, imagens e TODOS os ficheiros JavaScript da raiz
COPY index.html view.html logo.png /usr/share/nginx/html/
COPY *.js /usr/share/nginx/html/

COPY nginx.conf /etc/nginx/nginx.conf.template

ENV BACKEND_HOST=backend \
    BACKEND_PORT=5050

EXPOSE 80

CMD ["/bin/sh", "-c", \
    "envsubst '$BACKEND_HOST $BACKEND_PORT' < /etc/nginx/nginx.conf.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"]