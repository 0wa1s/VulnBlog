"use strict";
/**
 * grpc_server.js — gRPC server (port 50051)
 * Shares all handlers with app.js via handlers.js
 *
 * grpcurl quickstart:
 *   grpcurl -plaintext -import-path . -proto blog_service.proto \
 *     -d '{"username":"alice","password":"alice123"}' \
 *     localhost:50051 blog.VulnBlogService/Login
 */

const grpc        = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");
const path        = require("path");
const fs          = require("fs");
const crypto      = require("crypto");
const Database    = require("better-sqlite3");
const {ReflectionService} = require("@grpc/reflection");
const { makeHandlers } = require("./handlers");

const GRPC_PORT = 50051;
const GRPCS_PORT = 50052;
const DB_PATH   = "/data/vulnblog.db";

// ── Database (same file as HTTP server — shared sessions and data) ─────────────
fs.mkdirSync("/data", { recursive: true });
const db = new Database(DB_PATH);

// ── Session helpers ───────────────────────────────────────────────────────────
function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT OR IGNORE INTO sessions(token,user_id) VALUES (?,?)").run(token, userId);
  return token;
}
function resolveSession(token) {
  if (!token || typeof token !== "string" || token.length < 10) return null;
  return db.prepare("SELECT u.* FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=?").get(token) || null;
}
function deleteSession(token) {
  if (token) db.prepare("DELETE FROM sessions WHERE token=?").run(token);
}

// ── Handlers ──────────────────────────────────────────────────────────────────
const h = makeHandlers({ db, createSession, resolveSession, deleteSession });

// ── Load proto ────────────────────────────────────────────────────────────────
const pkgDef = protoLoader.loadSync(
  path.join(__dirname, "blog_service.proto"),
  { keepCase: false, longs: String, enums: String, defaults: true, oneofs: true }
);
const proto = grpc.loadPackageDefinition(pkgDef).blog;

// ── Adapter — wraps any handler into a gRPC call/callback ─────────────────────
function adapt(handler) {
  return (call, callback) => {
    try {
      const result = handler(call.request);
      callback(null, result);
    } catch (err) {
      callback({ code: grpc.status.INTERNAL, message: err.message });
    }
  };
}

// ── Service implementation ────────────────────────────────────────────────────
const serviceImpl = {
  Login:          adapt(h.handleLogin),
  Register:       adapt(h.handleRegister),
  Logout:         adapt(h.handleLogout),
  ListPosts:      adapt(h.handleListPosts),
  GetPost:        adapt(h.handleGetPost),
  Search:         adapt(h.handleSearch),
  CreatePost:     adapt(h.handleCreatePost),
  CreateComment:  adapt(h.handleCreateComment),
  FilterComments: adapt(h.handleFilterComments),
  PublishPost:    adapt(h.handlePublishPost),
  DeletePost:     adapt(h.handleDeletePost),
  UpdateProfile:  adapt(h.handleUpdateProfile),
};

// ── Start ─────────────────────────────────────────────────────────────────────
function startGrpc() {
  const server = new grpc.Server();
  server.addService(proto.VulnBlogService.service, serviceImpl);
  new ReflectionService(pkgDef).addToServer(server);
  
  // Code to enable TLS start
  // Load the certificates generated in the Dockerfile
  const rootCert = fs.readFileSync("cert.pem");
  const key      = fs.readFileSync("key.pem");
  const cert     = fs.readFileSync("cert.pem");
  const credentials = grpc.ServerCredentials.createSsl(
    rootCert, 
    [{ private_key: key, cert_chain: cert }], 
    false
  );
  server.bindAsync(
    `0.0.0.0:${GRPCS_PORT}`,
    credentials,
    (err, port) => {
      if (err) { console.error(`[VulnBlog gRPC] Failed to bind: ${err.message}`); return; }
      console.log(`[VulnBlog gRPC]  grpcs://0.0.0.0:${port} (TLS enabled)`);
    }
  );
  
  // // Code to enable TLS END
  
  // Cleartext GRPC code below
  
  server.bindAsync(
    `0.0.0.0:${GRPC_PORT}`,
    grpc.ServerCredentials.createInsecure(),
    (err, port) => {
      if (err) { console.error(`[VulnBlog gRPC] Failed to bind: ${err.message}`); return; }
      console.log(`[VulnBlog gRPC]  grpc://0.0.0.0:${port}  (plaintext)`);
      console.log(`[VulnBlog gRPC]  grpcurl -plaintext localhost:${port} blog.VulnBlogService/Login`);
    }
  );
  
}

module.exports = { startGrpc };
