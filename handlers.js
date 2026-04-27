"use strict";
/**
 * handlers.js — VulnBlog business logic
 *
 * SQL Injection is INTENTIONALLY present in two specific places only:
 *   1. handleLogin        — username + password fields  (classic login bypass)
 *   2. handleSearch       — tags field only             (UNION + error-based)
 *
 * All other database operations use parameterised statements (? bindings)
 * so that testing XSS, SSTI, and NoSQL does not accidentally trigger
 * SQL errors that mask the real vulnerability being studied.
 *
 * Vulnerability map:
 *   SQLi   — handleLogin (username/password), handleSearch (tags field)
 *   XSS    — handleCreatePost (post.body), handleCreateComment (comment.content)
 *   SSTI   — handleCreatePost (post.template → nunjucks.renderString, no sandbox)
 *   NoSQL  — handleFilterComments (filter → new Function().call(row))
 *   BAC    — handleUpdateProfile (author.role written to DB unchecked)
 *            handleListPosts / handleSearch (minRole trusted from client)
 */

const nunjucks = require("nunjucks");
const njkEnv   = new nunjucks.Environment(); // no sandbox — SSTI surface

// ── Row mappers ───────────────────────────────────────────────────────────────
function rowToPost(row) {
  return {
    id:         row.id         || 0,
    title:      row.title      || "",
    body:       row.body       || "",
    category:   row.category   || "",
    template:   row.template   || "",
    authorId:   row.author_id  || 0,
    tags:       row.tags       || "",
    published:  row.published  === 1,
    authorName: row.username   || "",
    created:    row.created    || "",
  };
}

function rowToComment(c) {
  return {
    id:      c.id,
    postId:  c.post_id,
    author:  c.author  || "",
    content: c.content || "",
    filter:  c.filter  || "",
    created: c.created || "",
  };
}

function userToAuthor(u) {
  return {
    id:       u.id,
    username: u.username,
    email:    u.email || "",
    role:     u.role,
    bio:      u.bio   || "",
  };
}

// ── Handler factory ───────────────────────────────────────────────────────────
function makeHandlers({ db, createSession, resolveSession, deleteSession }) {

  // Resolve Role enum — proto loader sends enums as strings ('ADMIN', 'GUEST')
  // Convert to integer so comparisons work correctly
  function resolveRole(val) {
    if (typeof val === 'number') return val;
    const map = { 'GUEST': 0, 'AUTHOR': 1, 'ADMIN': 2 };
    return map[val] !== undefined ? map[val] : parseInt(val, 10) || 0;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  AUTH
  // ══════════════════════════════════════════════════════════════════════════

  // ── LOGIN  ▸  VULN SQLi (username + password) ─────────────────────────────
  // This is the designated SQL injection surface for login bypass exercises.
  // Both fields are interpolated directly — no parameterisation.
  //
  // Payloads:
  //   username = admin'--          → comment out password check
  //   username = ' OR '1'='1'--   → always-true bypass
  function handleLogin({ username, password }) {
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    let rows;
    try { rows = db.prepare(sql).all(); }
    catch (e) { return { success: false, message: `SQL Error: ${e.message}` }; }
    if (!rows.length) return { success: false, message: "Invalid username or password" };
    const u     = rows[0];
    const token = createSession(u.id);
    return { success: true, loginResult: { success: true, sessionToken: token, user: userToAuthor(u) } };
  }

  // ── REGISTER  ▸  safe (parameterised) ────────────────────────────────────
  function handleRegister({ username, password, email }) {
    const existing = db.prepare("SELECT id FROM users WHERE username = ?").all(username);
    if (existing.length) return { success: false, message: "Username already taken" };
    try {
      db.prepare("INSERT INTO users(username,password,role,email,bio) VALUES (?,?,0,?,'New member.')")
        .run(username, password, email || "");
    } catch (e) { return { success: false, message: `Registration failed: ${e.message}` }; }
    const u     = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    const token = createSession(u.id);
    return { success: true, message: "Account created", loginResult: { success: true, sessionToken: token, user: userToAuthor(u) } };
  }

  // ── LOGOUT  ▸  safe ───────────────────────────────────────────────────────
  function handleLogout({ sessionToken }) {
    deleteSession(sessionToken);
    return { success: true, message: "Logged out" };
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  POSTS
  // ══════════════════════════════════════════════════════════════════════════

  // ── LIST POSTS  ▸  VULN BAC (minRole from client) — safe SQL ─────────────
  // VULN: server trusts client-supplied minRole with no authentication check.
  // If no valid session token is provided but minRole=2 (ADMIN) is sent,
  // the published=1 filter is skipped and all drafts are returned.
  function handleListPosts({ minRole, category, sessionToken }) {
    const sessionUser = resolveSession(sessionToken);

    // VULN BAC: minRole is trusted directly from the client.
    // No session required — unauthenticated callers can send minRole=2
    // and bypass the published filter entirely.
    const role = sessionUser ? sessionUser.role : resolveRole(minRole);

    // Parameterised — category filter is safe
    let sql    = role >= 2
      ? "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE 1=1"
      : "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE p.published=1";
    const params = [];
    if (category && category.trim()) { sql += " AND p.category LIKE ?"; params.push(`%${category.trim()}%`); }
    sql += " ORDER BY p.id DESC";

    const rows = db.prepare(sql).all(...params);
    return { success: true, searchResult: { posts: rows.map(rowToPost), total: rows.length, debug: sql } };
  }

  // ── GET POST  ▸  safe (parameterised) ────────────────────────────────────
  function handleGetPost({ postId, sessionToken }) {
    const sessionUser = resolveSession(sessionToken);
    const id          = parseInt(postId, 10);
    if (!id) return { success: false, message: "Invalid post ID" };

    const rows = db.prepare(
      "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE p.id=?"
    ).all(id);
    if (!rows.length) return { success: false, message: "Post not found" };

    const post = rows[0];
    if (!post.published) {
      if (!sessionUser)
        return { success: false, message: "This post is not published" };
      if (sessionUser.role < 2 && sessionUser.id !== post.author_id)
        return { success: false, message: "You do not have permission to view this post" };
    }

    const comments = db.prepare("SELECT * FROM comments WHERE post_id=? ORDER BY id DESC").all(id);
    return { success: true, postResult: rowToPost(post), commentList: comments.map(rowToComment) };
  }

  // ── SEARCH  ▸  VULN SQLi (tags field only) — query is safe ───────────────
  // tags is the designated SQL injection surface for search exercises.
  // query field is parameterised so keyword search works normally.
  //
  // Payloads go in the tags field:
  //   x%' order by 10 -- - UNION SELECT 1,username,password,...  FROM users--
  // 
  function handleSearch({ query, tags, minRole, sessionToken }) {
    const sessionUser = resolveSession(sessionToken);

    // VULN BAC: same as ListPosts — minRole trusted from client when no session
    const role = sessionUser ? sessionUser.role : resolveRole(minRole);

    let sql = role >= 2
      ? "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE 1=1"
      : "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE p.published=1";

    const params = [];
    if (query) {
      sql += " AND (p.title LIKE ? OR p.body LIKE ?)";   // safe
      params.push(`%${query}%`, `%${query}%`);
    }
    // VULN SQLi: tags is intentionally raw-interpolated
    if (tags) sql += ` AND p.tags LIKE '%${tags}%'`;
    sql += " ORDER BY p.id DESC";

    let rows;
    try { rows = db.prepare(sql).all(...params); }
    catch (e) { return { success: false, message: `SQL Error: ${e.message}`, searchResult: { debug: sql } }; }
    return { success: true, searchResult: { posts: rows.map(rowToPost), total: rows.length, debug: sql } };
  }

  // ── CREATE POST  ▸  VULN XSS (body) + SSTI (template) ──────────────────────
  // SQL is parameterised — creating a post will not break due to quotes in
  // the title/body/category fields. The vulnerabilities are:
  //   XSS:  body stored raw, reflected as innerHTML
  //   SSTI: template passed to nunjucks.renderString() with no sandbox
  function handleCreatePost({ sessionToken, post: p }) {
    const sessionUser = resolveSession(sessionToken);
    if (!sessionUser)        return { success: false, message: "Authentication required. Please log in." };
    if (sessionUser.role < 1) return { success: false, message: "You need Author or Admin role to create posts." };

    // VULN SSTI — template rendered through unsandboxed Nunjucks
    // require is passed in the context so payloads work on all Node versions
    let rendered = "";
    try {
      rendered = njkEnv.renderString(p.template || "", {
        title:    p.title,
        authorId: sessionUser.id,
        require:  require,          // expose require so child_process/fs payloads work
        process:  process,          // expose process for env dumps
        global:   global,           // expose global
      });
    } catch (e) {
      rendered = `[SSTI Error: ${e.message}]`;
    }

    // Parameterised INSERT — body/title/category with quotes won't break SQL
    // XSS surface: body is stored and reflected raw (SQL is safe, output is not)
    try {
      db.prepare(
        "INSERT INTO posts(title,body,category,template,author_id,tags,published) VALUES (?,?,?,?,?,?,?)"
      ).run(
        p.title || "",
        p.body  || "",      // VULN XSS: stored raw, no sanitisation
        p.category || "",
        p.template || "",   // VULN SSTI: rendered above
        sessionUser.id,
        p.tags || "",
        p.published ? 1 : 0
      );
    } catch (e) { return { success: false, message: `Failed to create post: ${e.message}` }; }

    const newId   = db.prepare("SELECT last_insert_rowid() as id").get().id;
    const newPost = db.prepare(
      "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE p.id=?"
    ).get(newId);

    return {
      success:   true,
      message:   rendered || "Post created",
      postResult: rowToPost(newPost),
    };
  }

  // ── PUBLISH POST  ▸  safe (parameterised) ────────────────────────────────
  // Flip published=0 → published=1 for a draft post.
  // Only the post author or an Admin can publish.
  function handlePublishPost({ sessionToken, postId }) {
    const sessionUser = resolveSession(sessionToken);
    if (!sessionUser) return { success: false, message: "Authentication required." };

    const id   = parseInt(postId, 10);
    const post = db.prepare("SELECT * FROM posts WHERE id=?").get(id);
    if (!post)               return { success: false, message: "Post not found." };
    if (post.published === 1) return { success: false, message: "Post is already published." };
    if (sessionUser.role < 2 && sessionUser.id !== post.author_id)
      return { success: false, message: "You can only publish your own posts." };

    db.prepare("UPDATE posts SET published=1 WHERE id=?").run(id);
    const updated = db.prepare(
      "SELECT p.*,u.username FROM posts p LEFT JOIN users u ON p.author_id=u.id WHERE p.id=?"
    ).get(id);
    return { success: true, message: `Post #${id} published.`, postResult: rowToPost(updated) };
  }

  // ── DELETE POST  ▸  safe (parameterised) ─────────────────────────────────
  // Permanently delete a post and its comments.
  // Author can delete their own posts. Admin can delete any.
  function handleDeletePost({ sessionToken, postId }) {
    const sessionUser = resolveSession(sessionToken);
    if (!sessionUser) return { success: false, message: "Authentication required." };

    const id   = parseInt(postId, 10);
    const post = db.prepare("SELECT * FROM posts WHERE id=?").get(id);
    if (!post) return { success: false, message: "Post not found." };
    if (sessionUser.role < 2 && sessionUser.id !== post.author_id)
      return { success: false, message: "You can only delete your own posts." };

    db.prepare("DELETE FROM comments WHERE post_id=?").run(id);
    db.prepare("DELETE FROM posts WHERE id=?").run(id);
    return { success: true, message: `Post #${id} and its comments have been deleted.` };
  }

  // ── CREATE COMMENT  ▸  VULN XSS (content) — safe SQL ─────────────────────
  // content is stored raw and reflected as innerHTML — XSS surface.
  // SQL is parameterised so quotes in content don't break the insert.
  function handleCreateComment({ sessionToken, comment: c }) {
    const sessionUser = resolveSession(sessionToken);
    if (!sessionUser) return { success: false, message: "Authentication required. Please log in to comment." };

    const author = sessionUser.username; // server-enforced, client cannot spoof
    try {
      db.prepare("INSERT INTO comments(post_id,author,content,filter) VALUES (?,?,?,?)")
        .run(parseInt(c.postId, 10), author, c.content || "", c.filter || "");
    } catch (e) { return { success: false, message: `Failed to save comment: ${e.message}` }; }

    const newId = db.prepare("SELECT last_insert_rowid() as id").get().id;
    return {
      success: true,
      message: "Comment saved.",
      commentResult: {
        id:      newId,
        postId:  c.postId,
        author,
        content: c.content || "", // VULN XSS: stored raw, reflected as innerHTML
        filter:  c.filter  || "",
        created: "just now",
      },
    };
  }

  // ── FILTER COMMENTS  ▸  VULN NoSQL/eval — safe SQL ───────────────────────
  // The filter expression is eval()'d as JavaScript with this=comment row.
  // SQL to load comments is parameterised — postId is safe.
  //
  // Legitimate:  this.author === 'alice'  /  this.content.length > 60
  // Malicious:   require('fs').readdirSync('/')  /  process.env
  function handleFilterComments({ postId, filter }) {
    const id          = parseInt(postId, 10);
    const allComments = db.prepare("SELECT * FROM comments WHERE post_id=? ORDER BY id DESC").all(id);

    if (!filter || !filter.trim())
      return { success: true, message: `${allComments.length} comment(s) (no filter)`, commentList: allComments.map(rowToComment) };

    const matched = [];
    let evalError = null;
    for (const row of allComments) {
      try {
        // VULN NoSQL/eval — require/process/global injected so all payloads work
        const fn = new Function('require', 'process', 'global', `return (${filter})`);
        if (fn.call(row, require, process, global)) matched.push(row);
      } catch (e) { evalError = e.message; break; }
    }
    if (evalError) return { success: false, message: `Filter error: ${evalError}` };
    return {
      success: true,
      message: `${matched.length} of ${allComments.length} comment(s) matched "${filter}"`,
      commentList: matched.map(rowToComment),
    };
  }

  // ── UPDATE PROFILE  ▸  VULN BAC (role from client) — safe SQL ─────────────
  // The role field is written to the DB exactly as supplied by the client —
  // no server-side validation that the requested role <= current role.
  // SQL is parameterised so quotes in bio/email don't break the update.
  function handleUpdateProfile({ sessionToken, author: a }) {
    const sessionUser = resolveSession(sessionToken);
    if (!sessionUser) return { success: false, message: "Authentication required." };
    if (sessionUser.role < 2 && sessionUser.id !== a.id)
      return { success: false, message: "You can only edit your own profile." };

    // VULN BAC: a.role is written unchecked — send role=2 to become Admin
    try {
      db.prepare("UPDATE users SET bio=?, email=?, role=? WHERE id=?")
        .run(a.bio || "", a.email || "", a.role || 0, parseInt(a.id, 10));
    } catch (e) { return { success: false, message: `Update failed: ${e.message}` }; }

    const u = db.prepare("SELECT * FROM users WHERE id=?").get(parseInt(a.id, 10));
    if (!u) return { success: false, message: "User not found" };

    deleteSession(sessionToken);
    const newToken = createSession(u.id);
    return {
      success: true,
      message: `Profile updated. Role is now ${a.role}. [BAC: role accepted from client without validation]`,
      loginResult: { success: true, sessionToken: newToken, user: userToAuthor(u) },
    };
  }

  return {
    handleLogin, handleRegister, handleLogout,
    handleListPosts, handleGetPost, handleSearch,
    handleCreatePost, handlePublishPost, handleDeletePost,
    handleCreateComment, handleFilterComments,
    handleUpdateProfile,
  };
}

module.exports = { makeHandlers, rowToPost, rowToComment, userToAuthor };
