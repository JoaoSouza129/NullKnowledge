"""
SecureShare - Backend API zero-knowledge para partilha de segredos.
O servidor armazena apenas blobs cifrados; nunca tem acesso ao plaintext.
"""
import logging
import os
import threading
import secrets  # Substituído uuid por secrets
from dataclasses import dataclass
from typing import Final

import redis
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_restx import Api, Namespace, Resource, fields

# ─── Configuração ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Config:
    redis_host: str
    redis_port: int
    redis_password: str | None
    max_secret_bytes: int
    max_ttl_seconds: int
    allowed_origin: str
    log_level: str

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            redis_host=os.getenv("REDIS_HOST", "localhost"),
            redis_port=int(os.getenv("REDIS_PORT", "6379")),
            redis_password=os.getenv("REDIS_PASSWORD"), # or None
            max_secret_bytes=int(os.getenv("MAX_SECRET_BYTES", "10000")),   # ~10 KB cifrado
            max_ttl_seconds=int(os.getenv("MAX_TTL_SECONDS", "604800")),    # 7 dias
            allowed_origin=os.getenv("ALLOWED_ORIGIN", "*"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )


CONFIG: Final[Config] = Config.from_env()

# ─── Logging (NUNCA loga conteúdo do segredo) ─────────────────────────────

logging.basicConfig(
    level=CONFIG.log_level,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("secure-share")

# ─── App e dependências ───────────────────────────────────────────────────
class Server():
    def __init__(self,):
        self.app= Flask(__name__)
        self.cors= CORS(self.app, origins=CONFIG.allowed_origin)
        self.api= Api(self.app,
                      version='1.0',
                      title="API do site amnesiashhh",
                      description="Uma API que encripta um segredo e devolve-o para quem tem o link, sem saber qual o segredo original",
                      doc="/docs"
                      )
    def run(self,):
        self.app.run(
            port=8081
        )

# ─── Inicialização do Servidor ────────────────────────────────────────────
server = Server()

# [CORREÇÃO 1]: Expor a instância do Flask globalmente para o Gunicorn a encontrar ("app:app")
app = server.app  

# ─── [SOLUÇÃO DE SEGURANÇA WEB]: Injeção Global de Cabeçalhos HTTP ───────
@app.after_request
def inject_security_headers(response):
    """Aplica as políticas de CSP, COEP e CORS corretas a todas as respostas."""
    
    # Resolve o erro ERR_BLOCKED_BY_RESPONSE do COEP, permitindo CDNs externos
    response.headers["Cross-Origin-Embedder-Policy"] = "unsafe-none"
    
    # Política CSP unificada para o teu Frontend, API e documentação Swagger (/docs)
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://amnesia-shh.duckdns.org; "
        "img-src 'self' data: https://online.swagger.io;"
    )
    response.headers["Content-Security-Policy"] = csp_policy
    
    # Garante que as credenciais de CORS funcionam em ambientes de produção
    response.headers["Access-Control-Allow-Origin"] = CONFIG.allowed_origin
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    
    return response


db: Final[redis.Redis] = redis.Redis(
    host=CONFIG.redis_host,
    port=CONFIG.redis_port,
    password=CONFIG.redis_password,
    decode_responses=True,
    socket_connect_timeout=2,
)

# ─── Redis Keyspace Notifications (log de expiração por TTL) ──────────────

def _start_expiration_listener() -> None:
    """Subscreve eventos de expiração do Redis numa thread daemon.

    Requer notify-keyspace-events com pelo menos 'Ex'.
    A config é aplicada automaticamente no arranque.
    """
    def _listen():
        try:
            # Ativa notificações de expiração (idempotente)
            db.config_set("notify-keyspace-events", "Ex")
            log.info("redis_keyspace_notifications enabled (Ex)")
        except redis.RedisError as e:
            log.warning("could not enable keyspace notifications: %s", e)
            return

        # Ligação dedicada para pub/sub (bloqueante)
        pubsub = db.pubsub()
        pubsub.subscribe("__keyevent@0__:expired")
        log.info("expiration_listener started")

        for message in pubsub.listen():
            if message["type"] != "message":
                continue
            key = message["data"]
            if isinstance(key, bytes):
                key = key.decode("utf-8", errors="replace")

            # Ignora chaves de metadata (meta:uuid) para não duplicar logs
            if key.startswith("meta:"):
                continue

            log.info("secret_expired id=%s reason=ttl", key)

    t = threading.Thread(target=_listen, name="redis-expiry-listener", daemon=True)
    t.start()


_start_expiration_listener()

# ─── Swagger Models ──────────────────────────────────────────────────────
api = server.api

ns_secrets = Namespace('secrets', path='/api/secrets', description='Operações de gestão de segredos')

ns_health = Namespace('health', path='/', description='Status da aplicação')

# Modelos de Request/Response
secret_create_model = api.model('SecretCreate', {
    'content': fields.String(required=True, description='Conteúdo do segredo (blob cifrado)', example='aGVsbG8gd29ybGQ='),
    'ttl': fields.Integer(required=False, description='Time-to-live em segundos (default: 3600)', example=3600),
    'one_time': fields.Boolean(required=False, description='Se verdadeiro, o segredo é apagado após leitura (default: true)', example=True)
})

secret_create_response = api.model('SecretCreateResponse', {
    'id': fields.String(description='ID único do segredo gerado', example='aB3dE7fG9hK')
})

secret_read_response = api.model('SecretReadResponse', {
    'content': fields.String(description='Conteúdo do segredo (blob cifrado)', example='aGVsbG8gd29ybGQ=')
})

error_response = api.model('Error', {
    'error': fields.String(description='Mensagem de erro', example='not found or expired')
})

health_response = api.model('HealthStatus', {
    'status': fields.String(description='Status da aplicação', example='ok')
})

# Registar namespaces
api.add_namespace(ns_secrets)
api.add_namespace(ns_health)

# ─── Endpoints de Segredos ────────────────────────────────────────────────
@ns_secrets.route('')
class SecretsList(Resource):
    @ns_secrets.doc('create_secret', params={})
    @ns_secrets.expect(secret_create_model)
    @ns_secrets.response(201, 'Segredo criado com sucesso', secret_create_response)
    @ns_secrets.response(400, 'Conteúdo em falta ou inválido', error_response)
    @ns_secrets.response(413, 'Segredo demasiado grande', error_response)
    def post(self):
        """Cria um novo segredo cifrado e devolve um ID único"""
        data = request.get_json()
        if not data or "content" not in data:
            return {"error": "missing content"}, 400

        content = data["content"]
        if len(content.encode("utf-8")) > CONFIG.max_secret_bytes:
            return {"error": "secret too large"}, 413

        ttl = data.get("ttl", 3600)
        try:
            ttl = int(ttl)
            if ttl <= 0 or ttl > CONFIG.max_ttl_seconds:
                ttl = CONFIG.max_ttl_seconds
        except ValueError:
            ttl = 3600

        one_time = bool(data.get("one_time", True))

        # Geração de Short ID seguro (12 caracteres alfanuméricos/símbolos seguros)
        secret_id = secrets.token_urlsafe(9)

        pipe = db.pipeline()
        pipe.set(name=secret_id, value=content, ex=ttl)
        pipe.set(name=f"meta:{secret_id}", value="1" if one_time else "0", ex=ttl)
        pipe.execute()

        log.info("secret_created id=%s ttl=%d one_time=%s", secret_id, ttl, one_time)
        return {"id": secret_id}, 201


@ns_secrets.route('/<string:secret_id>')
class SecretsDetail(Resource):
    @ns_secrets.doc('read_secret', params={'secret_id': 'ID único do segredo'})
    @ns_secrets.response(200, 'Segredo recuperado com sucesso', secret_read_response)
    @ns_secrets.response(400, 'Formato de ID inválido', error_response)
    @ns_secrets.response(404, 'Segredo não encontrado ou expirou', error_response)
    def get(self, secret_id):
        """Recupera um segredo cifrado pelo ID. Se for one-time, apaga-o após leitura."""
        
        # Validação de segurança para Short IDs (apenas alfanuméricos, hífen e underscore)
        # Impede caracteres maliciosos de subirem para o Redis
        if not all(c.isalnum() or c in ["-", "_"] for c in secret_id):
            return {"error": "invalid id format"}, 400

        is_one_time = db.get(f"meta:{secret_id}") == "1"

        if is_one_time:
            raw_content = db.execute_command("GETDEL", secret_id)
            db.delete(f"meta:{secret_id}")
            
            if isinstance(raw_content, bytes):
                content = raw_content.decode('utf-8')
            else:
                content = raw_content
        else:
            content = db.get(secret_id)

        if content is None:
            log.info("secret_miss id=%s", secret_id)
            return {"error": "not found or expired"}, 404

        log.info("secret_read id=%s one_time=%s", secret_id, is_one_time)
        return {"content": content}, 200


# ─── Endpoints de Status ──────────────────────────────────────────────────

@ns_health.route('/healthz')
class HealthReadiness(Resource):
    @ns_health.doc('healthz')
    @ns_health.response(200, 'Serviço pronto', health_response)
    @ns_health.response(503, 'Serviço indisponível', error_response)
    def get(self):
        """Verifica se a aplicação está pronta para receber requisições"""
        try:
            db.ping()
            return {"status": "ok"}, 200
        except redis.RedisError as e:
            log.warning("health_check_failed: %s", e)
            return {"status": "unavailable"}, 503

if __name__ == "__main__":
    server.run()