# ════════════════════════════════════════════════════════════════════
#  VulnBlog — Intentionally Vulnerable Application
#  FOR SECURITY RESEARCH AND CTF USE ONLY
#
#  Ports:
#    3000  — HTTP/1.1  (browser SPA + binary Protobuf API)
#    50051 — gRPC      (plaintext, use with grpcurl)
#    50052 - gRPCS
#  Build:   docker build -t vulnblog .
#  Run:     docker compose up -d --build
#
#  grpcurl quickstart:
#    grpcurl -plaintext -import-path . -proto blog_service.proto \
#      -d '{"username":"alice","password":"alice123"}' \
#      localhost:50051 blog.VulnBlogService/Login
#
#  DB persists in Docker volume across restarts.
#  To reset: docker compose down -v && docker compose up -d --build
# ════════════════════════════════════════════════════════════════════

FROM node:22-bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-pip make g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Generate self-signed certificates for TLS
RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj '/CN=localhost'

# Deps layer (cached unless package.json changes)
COPY package.json ./
RUN npm install --omit=dev

# Application source
COPY app.js          ./
COPY handlers.js     ./
COPY grpc_server.js  ./
COPY blog.proto      ./
COPY blog_service.proto ./
COPY public/         ./public/
COPY exploits/       ./exploits/

VOLUME ["/data"]

# HTTP + gRPC + gRPCS
EXPOSE 3000 50051 50052

CMD ["node", "app.js"]
