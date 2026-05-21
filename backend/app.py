"""
SecureShare - Backend API zero-knowledge para partilha de segredos.
O servidor armazena apenas blobs cifrados; nunca tem acesso ao plaintext.
"""
import logging
import os
import threading
import secrets  # Substituído uuid por secrets
import uvicorn  # Caso uses para o startup
from dataclasses import dataclass
from typing import Final

import redis
from flask import Flask, jsonify, request
from flask_cors import CORS

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

app = Flask(__name__)
CORS(app, origins=CONFIG.allowed_origin)   # CORS restrito, não aberto

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

# ─── Endpoints ────────────────────────────────────────────────────────────

@app.route("/api/secrets", methods=["POST"])
def create_secret():
    """Recebe o blob cifrado e armazena-o sob um Short ID gerado de forma segura."""
    data = request.get_json()
    if not data or "content" not in data:
        return jsonify({"error": "missing content"}), 400

    content = data["content"]
    if len(content.encode("utf-8")) > CONFIG.max_secret_bytes:
        return jsonify({"error": "secret too large"}), 413

    ttl = data.get("ttl", 3600)
    try:
        ttl = int(ttl)
        if ttl <= 0 or ttl > CONFIG.max_ttl_seconds:
            ttl = CONFIG.max_ttl_seconds
    except ValueError:
        ttl = 3600

    one_time = bool(data.get("one_time", True))

    # ALTERAÇÃO: Geração de Short ID seguro (12 caracteres alfanuméricos/símbolos seguros)
    secret_id = secrets.token_urlsafe(9)

    pipe = db.pipeline()
    pipe.set(name=secret_id, value=content, ex=ttl)
    pipe.set(name=f"meta:{secret_id}", value="1" if one_time else "0", ex=ttl)
    pipe.execute()

    log.info("secret_created id=%s ttl=%d one_time=%s", secret_id, ttl, one_time)
    return jsonify({"id": secret_id}), 201


@app.route("/api/secrets/<secret_id>", methods=["GET"])
def read_secret(secret_id: str):
    """Devolve o blob cifrado; apaga atomicamente se for one-time."""
    
    # ALTERAÇÃO: Validação de segurança para Short IDs (apenas alfanuméricos, hífen e underscore)
    # Impede caracteres maliciosos de subirem para o Redis
    if not secret_id.isalnum() and not any(c in secret_id for c in ["-", "_"]):
        return jsonify({"error": "invalid id format"}), 400

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
        return jsonify({"error": "not found or expired"}), 404

    log.info("secret_read id=%s one_time=%s", secret_id, is_one_time)
    return jsonify({"content": content}), 200


@app.route("/healthz", methods=["GET"])
def health():
    """Liveness/readiness probe. Devolve 503 se o Redis estiver indisponível."""
    try:
        db.ping()
        return jsonify({"status": "ok"}), 200
    except redis.RedisError as e:
        log.warning("health_check_failed: %s", e)
        return jsonify({"status": "unavailable"}), 503


if __name__ == "__main__":
    # Apenas para desenvolvimento. Em produção corre com gunicorn (ver Dockerfile).
    app.run(host="0.0.0.0", port=5050)
