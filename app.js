"use strict";
/**
 * app.js — HTTP/1.1 server (port 3000)
 * Browser SPA + binary Protobuf API at POST /api/proto
 * All business logic lives in handlers.js (shared with grpc_server.js)
 */
// to enable TLS uncomment this
//const https = require("https");
const express  = require("express");
const path     = require("path");
const fs       = require("fs");
const crypto   = require("crypto");
const Database = require("better-sqlite3");
const protobuf = require("protobufjs");

const { makeHandlers } = require("./handlers");
const { startGrpc }    = require("./grpc_server");

const app     = express();
const PORT    = 3000;
const DB_PATH = "/data/vulnblog.db";

// ── Database ──────────────────────────────────────────────────────────────────
fs.mkdirSync("/data", { recursive: true });
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role     INTEGER DEFAULT 0,
    email    TEXT,
    bio      TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS posts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    title     TEXT,
    body      TEXT,
    category  TEXT,
    template  TEXT,
    author_id INTEGER,
    tags      TEXT,
    published INTEGER DEFAULT 1,
    created   TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS comments (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    author  TEXT,
    content TEXT,
    filter  TEXT,
    created TEXT DEFAULT (datetime('now'))
  );
`);

// Seed on first boot
if (db.prepare("SELECT COUNT(*) as c FROM users").get().c === 0) {
  db.exec(`
    INSERT INTO users(username,password,role,email,bio) VALUES
      ('admin','s3cr3tAdm1n!',2,'admin@vulnblog.local','Site administrator. Keeps the lights on.'),
      ('alice','alice123',1,'alice@vulnblog.local','Tech writer, coffee enthusiast, and occasional hacker.'),
      ('bob','bob456',0,'bob@vulnblog.local','Weekend blogger with too many opinions.');

    INSERT INTO posts(title,body,category,template,author_id,tags,published) VALUES
      ('Welcome to VulnBlog',
       '<p>Welcome to <strong>VulnBlog</strong> — a place where ideas meet the page.</p><p>Whether you are a developer, researcher, or curious reader, there is something here for you.</p>',
       'Announcements','Welcome to {{ title }}! We are glad you are here.',1,'welcome,intro',1),

      ('Understanding Protocol Buffers',
       '<p>Protocol Buffers are Google''s language-neutral serialization format — think XML, but smaller and faster.</p><p>Our entire API uses Protobuf — download the schema from the sidebar.</p>',
       'Technology','Read more about {{ title }} on our blog.',1,'protobuf,api,serialization,grpc',1),

      ('OWASP Top 10 — What Every Developer Must Know',
       '<p>The OWASP Top 10 represents the most critical security risks to web applications. Injection flaws, Broken Access Control, and XSS remain at the top year after year.</p>',
       'Security','Security matters. {{ title }} explains why.',2,'security,owasp,webdev,injection',1),

      ('The Art of Minimalist Writing',
       '<p>Good writing strips away the unnecessary. Every word should earn its place on the page.</p><p>Short sentences. Active voice. Concrete nouns.</p>',
       'Writing','Explore {{ title }} for tips on cleaner prose.',1,'writing,craft,minimalism',1),

      ('[DRAFT] Internal Admin Notes — DO NOT PUBLISH',
       '<p><strong>Credentials:</strong> admin / s3cr3tAdm1n!<br>DB passphrase: vulnblog-backup-2024</p><p>TODO: patch SQLi, sanitise XSS, remove eval(), fix BAC.</p>',
       'Internal','INTERNAL ONLY — {{ title }}',1,'internal,credentials,secret',0);

    INSERT INTO comments(post_id,author,content,filter) VALUES
      (1,'bob','Really great to see this blog launch! Looking forward to reading more.',''),
      (1,'alice','Thanks for the warm welcome — excited to contribute!',''),
      (2,'bob','Protobuf is so much faster than JSON in my benchmarks.',''),
      (3,'alice','OWASP Top 10 is essential reading for every developer. Bookmarked.',''),
      (3,'bob','SQL injection is still number one after all these years — says a lot.','');
  `);
}

// ── Session helpers ───────────────────────────────────────────────────────────
function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions(token,user_id) VALUES (?,?)").run(token, userId);
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

// ── Protobuf ──────────────────────────────────────────────────────────────────
let ApiRequest, ApiResponse;
async function initProto() {
  const root = await protobuf.load(path.join(__dirname, "blog.proto"));
  ApiRequest  = root.lookupType("blog.ApiRequest");
  ApiResponse = root.lookupType("blog.ApiResponse");
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.raw({ type: "application/x-protobuf", limit: "4mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── Protobuf response helper ──────────────────────────────────────────────────
function sendProto(res, obj) {
  const buf = ApiResponse.encode(ApiResponse.create(obj)).finish();
  res.setHeader("Content-Type", "application/x-protobuf");
  res.send(Buffer.from(buf));
}

// ── API endpoint ──────────────────────────────────────────────────────────────
app.post("/api/proto", (req, res) => {
  if (!Buffer.isBuffer(req.body) || req.body.length === 0)
    return res.status(400).json({ error: "Body must be binary protobuf" });

  let request;
  try { request = ApiRequest.decode(req.body); }
  catch (e) { return res.status(400).json({ error: "Decode failed: " + e.message }); }

  const kind = request.payload;
  let result;

  if      (kind === "login")          result = h.handleLogin(request.login);
  else if (kind === "register")       result = h.handleRegister(request.register);
  else if (kind === "logout")         result = h.handleLogout(request.logout);
  else if (kind === "listPosts")      result = h.handleListPosts(request.listPosts);
  else if (kind === "getPost")        result = h.handleGetPost(request.getPost);
  else if (kind === "search")         result = h.handleSearch(request.search);
  else if (kind === "post")           result = h.handleCreatePost(request.post);
  else if (kind === "comment")        result = h.handleCreateComment(request.comment);
  else if (kind === "filterComments") result = h.handleFilterComments(request.filterComments);
  else if (kind === "publishPost")    result = h.handlePublishPost(request.publishPost);
  else if (kind === "deletePost")     result = h.handleDeletePost(request.deletePost);
  else if (kind === "profile")        result = h.handleUpdateProfile(request.profile);
  else result = { success: false, message: `Unknown payload: "${kind}"` };

  sendProto(res, result);
});

// ── Proto downloads ───────────────────────────────────────────────────────────
app.get("/blog.proto", (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="blog.proto"');
  res.sendFile(path.join(__dirname, "blog.proto"));
});
app.get("/blog_service.proto", (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="blog_service.proto"');
  res.sendFile(path.join(__dirname, "blog_service.proto"));
});

// ── SPA catch-all ─────────────────────────────────────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
/* TO enable TLS
const options = {
  key:  fs.readFileSync("key.pem"),
  cert: fs.readFileSync("cert.pem")
};
*/
// ── Boot ──────────────────────────────────────────────────────────────────────
initProto().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[VulnBlog HTTP]  http://0.0.0.0:${PORT}`);
    console.log(`[VulnBlog HTTP]  DB: ${DB_PATH}`);
  });
  startGrpc();
});
