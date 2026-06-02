FROM nginx:1.27-alpine

# Limpa o lixo padrão do Nginx para evitar conflitos
RUN rm -rf /usr/share/nginx/html/*

# Copia TODOS os ficheiros da diretoria atual para o servidor estático
COPY . /usr/share/nginx/html/

# Configuração do template do proxy para o backend
COPY nginx.conf /etc/nginx/nginx.conf.template

ENV BACKEND_HOST=backend \
    BACKEND_PORT=5050

EXPOSE 80

CMD ["/bin/sh", "-c", \
    "envsubst '$BACKEND_HOST $BACKEND_PORT' < /etc/nginx/nginx.conf.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"]