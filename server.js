const { createHash, randomBytes, randomInt, scryptSync, timingSafeEqual } = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const nodemailer = require("nodemailer");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");

const envPath = path.join(__dirname, ".env");
if (fs.existsSync(envPath)) process.loadEnvFile(envPath);

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "localhost";
const PUBLIC_DIR = path.join(__dirname, "public");
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "ar-games.sqlite");
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const VERIFICATION_TTL_MS = 10 * 60 * 1000;
const VERIFICATION_RESEND_MS = 60 * 1000;
const MAX_VERIFICATION_ATTEMPTS = 5;
const COOKIE_NAME = "ar_games_session";
const database = new DatabaseSync(DB_PATH);

database.exec(`
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS favorites (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    game_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, game_id)
  );
  CREATE TABLE IF NOT EXISTS pending_registrations (
    email TEXT PRIMARY KEY COLLATE NOCASE,
    username TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    code_salt TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_sent_at INTEGER NOT NULL
  );
`);

const games = [];

const gameIds = new Set(games.map((game) => game.id));
const rateLimits = new Map();
let emailTransporter;
const statements = {
  userByEmail: database.prepare("SELECT * FROM users WHERE email = ?"),
  userById: database.prepare("SELECT id, username, email, created_at FROM users WHERE id = ?"),
  createUser: database.prepare("INSERT INTO users (username, email, password_salt, password_hash) VALUES (?, ?, ?, ?)"),
  createSession: database.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)"),
  sessionUser: database.prepare(`
    SELECT users.id, users.username, users.email, users.created_at
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `),
  deleteSession: database.prepare("DELETE FROM sessions WHERE token_hash = ?"),
  deleteExpiredSessions: database.prepare("DELETE FROM sessions WHERE expires_at <= ?"),
  pendingByEmail: database.prepare("SELECT * FROM pending_registrations WHERE email = ?"),
  savePendingRegistration: database.prepare(`
    INSERT INTO pending_registrations (
      email, username, password_salt, password_hash, code_salt, code_hash, expires_at, attempts, last_sent_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
    ON CONFLICT(email) DO UPDATE SET
      username = excluded.username,
      password_salt = excluded.password_salt,
      password_hash = excluded.password_hash,
      code_salt = excluded.code_salt,
      code_hash = excluded.code_hash,
      expires_at = excluded.expires_at,
      attempts = 0,
      last_sent_at = excluded.last_sent_at
  `),
  updatePendingCode: database.prepare(`
    UPDATE pending_registrations
    SET code_salt = ?, code_hash = ?, expires_at = ?, attempts = 0, last_sent_at = ?
    WHERE email = ?
  `),
  incrementVerificationAttempts: database.prepare("UPDATE pending_registrations SET attempts = attempts + 1 WHERE email = ?"),
  deletePendingRegistration: database.prepare("DELETE FROM pending_registrations WHERE email = ?"),
  listFavorites: database.prepare("SELECT game_id FROM favorites WHERE user_id = ? ORDER BY created_at DESC"),
  addFavorite: database.prepare("INSERT OR IGNORE INTO favorites (user_id, game_id) VALUES (?, ?)"),
  deleteFavorite: database.prepare("DELETE FROM favorites WHERE user_id = ? AND game_id = ?")
};

function sendJson(response, status, value, headers = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...headers
  });
  response.end(JSON.stringify(value));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 16_384) {
        reject(Object.assign(new Error("Request body is too large."), { status: 413 }));
        request.destroy();
      }
    });
    request.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch {
        reject(Object.assign(new Error("Invalid request data."), { status: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function getCookies(request) {
  const cookies = new Map();
  for (const part of (request.headers.cookie || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0) {
      cookies.set(part.slice(0, separator).trim(), part.slice(separator + 1).trim());
    }
  }
  return cookies;
}

function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

function sessionCookie(token, request) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${secure}`;
}

function clearSessionCookie(request) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`;
}

function getCurrentUser(request) {
  const token = getCookies(request).get(COOKIE_NAME);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  return statements.sessionUser.get(hashToken(token), Date.now()) || null;
}

function checkSameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return;
  let originUrl;
  try {
    originUrl = new URL(origin);
  } catch {
    throw Object.assign(new Error("Invalid request origin."), { status: 403 });
  }
  if (originUrl.host !== request.headers.host) {
    throw Object.assign(new Error("Request origin not allowed."), { status: 403 });
  }
}

function limitAuthAttempts(request) {
  const now = Date.now();
  const address = request.socket.remoteAddress || "unknown";
  const entry = rateLimits.get(address);
  if (!entry || entry.expiresAt <= now) {
    rateLimits.set(address, { count: 1, expiresAt: now + 15 * 60 * 1000 });
    return;
  }
  entry.count += 1;
  if (entry.count > 12) {
    throw Object.assign(new Error("Too many attempts. Please try again later."), { status: 429 });
  }
}

function passwordHash(password, salt) {
  return scryptSync(password, salt, 64).toString("hex");
}

function verificationCodeHash(code, salt) {
  return createHash("sha256").update(salt).update(code).digest("hex");
}

function getEmailTransporter() {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const password = process.env.SMTP_PASS;
  const port = Number(process.env.SMTP_PORT) || 465;
  if (!host || !user || !password) {
    throw Object.assign(new Error("Email delivery is not configured. Add SMTP_HOST, SMTP_USER, and SMTP_PASS to the server's .env file."), { status: 503 });
  }
  if (!emailTransporter) {
    emailTransporter = nodemailer.createTransport({
      host,
      port,
      secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE.toLowerCase() === "true" : port === 465,
      auth: { user, pass: password },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 15_000
    });
  }
  return emailTransporter;
}

async function sendVerificationEmail(email, code) {
  const transporter = getEmailTransporter();
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  try {
    await transporter.sendMail({
      from,
      to: email,
      subject: "Your AR GAMES verification code",
      text: `Your AR GAMES verification code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:32px auto;padding:32px;background:#111216;color:#f3f0e9"><p style="color:#f35e42;font-weight:bold;letter-spacing:2px">AR GAMES</p><h1 style="font-size:22px">Verify your email</h1><p>Enter this code to finish creating your account:</p><p style="font-size:36px;font-weight:bold;letter-spacing:10px;padding:12px 0">${code}</p><p style="color:#aaa">This code expires in 10 minutes. If you did not request this, you can ignore this email.</p></div>`
    });
  } catch (error) {
    console.error("Verification email delivery failed:", error);
    throw Object.assign(new Error("We couldn't send the verification email. Check your SMTP settings and try again."), { status: 502 });
  }
}

function createVerificationCode() {
  const code = String(randomInt(100_000, 1_000_000));
  const salt = randomBytes(16).toString("hex");
  return { code, salt, hash: verificationCodeHash(code, salt) };
}

function startSession(response, request, userId) {
  const token = randomBytes(32).toString("hex");
  statements.deleteExpiredSessions.run(Date.now());
  statements.createSession.run(hashToken(token), userId, Date.now() + SESSION_TTL_MS);
  response.setHeader("Set-Cookie", sessionCookie(token, request));
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    createdAt: user.created_at,
    favorites: statements.listFavorites.all(user.id)
      .map((favorite) => favorite.game_id)
      .filter((gameId) => gameIds.has(gameId))
  };
}

async function handleApi(request, response, url) {
  if (request.method === "GET" && url.pathname === "/api/games") {
    return sendJson(response, 200, { games });
  }

  if (request.method === "GET" && url.pathname === "/api/me") {
    const user = getCurrentUser(request);
    return sendJson(response, 200, { user: user ? publicUser(user) : null });
  }

  if (request.method === "POST" && ["/api/register", "/api/verify-email", "/api/resend-verification", "/api/login", "/api/logout", "/api/favorites"].includes(url.pathname)) {
    checkSameOrigin(request);
  }

  if (request.method === "POST" && url.pathname === "/api/register") {
    limitAuthAttempts(request);
    const body = await readBody(request);
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (username.length < 2 || username.length > 30) {
      return sendJson(response, 400, { error: "Username must be between 2 and 30 characters." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return sendJson(response, 400, { error: "Enter a valid email address." });
    }
    if (password.length < 8 || password.length > 128) {
      return sendJson(response, 400, { error: "Password must be at least 8 characters." });
    }
    if (statements.userByEmail.get(email)) {
      return sendJson(response, 409, { error: "An account with this email already exists." });
    }
    const pending = statements.pendingByEmail.get(email);
    if (pending && Date.now() - pending.last_sent_at < VERIFICATION_RESEND_MS) {
      return sendJson(response, 429, { error: "A verification code was already sent. Check your inbox or wait before requesting another." });
    }
    const salt = randomBytes(16).toString("hex");
    const hash = passwordHash(password, salt);
    const verification = createVerificationCode();
    await sendVerificationEmail(email, verification.code);
    const now = Date.now();
    statements.savePendingRegistration.run(
      email, username, salt, hash, verification.salt, verification.hash, now + VERIFICATION_TTL_MS, now
    );
    return sendJson(response, 202, {
      verificationRequired: true,
      email,
      message: "We sent a 6-digit verification code to your email address."
    });
  }

  if (request.method === "POST" && url.pathname === "/api/resend-verification") {
    limitAuthAttempts(request);
    const body = await readBody(request);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return sendJson(response, 400, { error: "Enter a valid email address." });
    }
    const pending = statements.pendingByEmail.get(email);
    if (!pending) {
      return sendJson(response, 400, { error: "No pending registration was found. Please create your account again." });
    }
    const waitMs = VERIFICATION_RESEND_MS - (Date.now() - pending.last_sent_at);
    if (waitMs > 0) {
      return sendJson(response, 429, { error: `Please wait ${Math.ceil(waitMs / 1000)} seconds before requesting another code.` });
    }
    const verification = createVerificationCode();
    await sendVerificationEmail(email, verification.code);
    const now = Date.now();
    statements.updatePendingCode.run(verification.salt, verification.hash, now + VERIFICATION_TTL_MS, now, email);
    return sendJson(response, 200, { message: "A new verification code has been sent." });
  }

  if (request.method === "POST" && url.pathname === "/api/verify-email") {
    limitAuthAttempts(request);
    const body = await readBody(request);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const code = typeof body.code === "string" ? body.code.trim() : "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return sendJson(response, 400, { error: "Enter a valid email address." });
    }
    if (!/^\d{6}$/.test(code)) {
      return sendJson(response, 400, { error: "Enter the 6-digit verification code." });
    }
    const pending = statements.pendingByEmail.get(email);
    if (!pending) {
      return sendJson(response, 400, { error: "No pending registration was found. Please create your account again." });
    }
    if (pending.expires_at <= Date.now()) {
      statements.deletePendingRegistration.run(email);
      return sendJson(response, 400, { error: "This code has expired. Request a new code to continue." });
    }
    if (pending.attempts >= MAX_VERIFICATION_ATTEMPTS) {
      return sendJson(response, 429, { error: "Too many incorrect codes. Request a new code to continue." });
    }
    const expectedHash = Buffer.from(pending.code_hash, "hex");
    const actualHash = Buffer.from(verificationCodeHash(code, pending.code_salt), "hex");
    if (expectedHash.length !== actualHash.length || !timingSafeEqual(expectedHash, actualHash)) {
      statements.incrementVerificationAttempts.run(email);
      const attemptsLeft = MAX_VERIFICATION_ATTEMPTS - pending.attempts - 1;
      return sendJson(response, 400, {
        error: attemptsLeft > 0
          ? `Incorrect verification code. ${attemptsLeft} attempts remaining.`
          : "Incorrect verification code. Request a new code to continue."
      });
    }
    if (statements.userByEmail.get(email)) {
      statements.deletePendingRegistration.run(email);
      return sendJson(response, 409, { error: "An account with this email already exists." });
    }
    const result = statements.createUser.run(pending.username, email, pending.password_salt, pending.password_hash);
    const user = statements.userById.get(Number(result.lastInsertRowid));
    statements.deletePendingRegistration.run(email);
    startSession(response, request, user.id);
    return sendJson(response, 201, { user: publicUser(user) });
  }

  if (request.method === "POST" && url.pathname === "/api/login") {
    limitAuthAttempts(request);
    const body = await readBody(request);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const user = statements.userByEmail.get(email);
    const suppliedHash = passwordHash(password.slice(0, 128), user?.password_salt || "invalid-account-salt");
    const validHash = user ? Buffer.from(user.password_hash, "hex") : Buffer.alloc(64);
    const actualHash = Buffer.from(suppliedHash, "hex");
    if (!user || actualHash.length !== validHash.length || !timingSafeEqual(actualHash, validHash)) {
      return sendJson(response, 401, { error: "Incorrect email or password." });
    }
    startSession(response, request, user.id);
    return sendJson(response, 200, { user: publicUser(user) });
  }

  if (request.method === "POST" && url.pathname === "/api/logout") {
    const token = getCookies(request).get(COOKIE_NAME);
    if (token && /^[a-f0-9]{64}$/.test(token)) statements.deleteSession.run(hashToken(token));
    return sendJson(response, 200, { success: true }, { "Set-Cookie": clearSessionCookie(request) });
  }

  if (request.method === "POST" && url.pathname === "/api/favorites") {
    const user = getCurrentUser(request);
    if (!user) return sendJson(response, 401, { error: "Sign in to save your favorites." });
    const body = await readBody(request);
    if (typeof body.gameId !== "string" || !gameIds.has(body.gameId)) {
      return sendJson(response, 400, { error: "Game not found." });
    }
    if (body.favorite === true) {
      statements.addFavorite.run(user.id, body.gameId);
    } else if (body.favorite === false) {
      statements.deleteFavorite.run(user.id, body.gameId);
    } else {
      return sendJson(response, 400, { error: "Invalid favorite setting." });
    }
    return sendJson(response, 200, {
      favorites: statements.listFavorites.all(user.id).map((favorite) => favorite.game_id)
    });
  }

  if (url.pathname.startsWith("/api/")) {
    return sendJson(response, 404, { error: "Route not found." });
  }

  return false;
}

function serveStatic(request, response, url) {
  const requestedPath = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const projectAssets = new Set(["/styles.css", "/app.js"]);
  const assetPath = projectAssets.has(requestedPath)
    ? path.resolve(__dirname, `.${requestedPath}`)
    : path.resolve(PUBLIC_DIR, `.${requestedPath}`);
  if (!assetPath.startsWith(`${PUBLIC_DIR}${path.sep}`) && !projectAssets.has(requestedPath)) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }
  fs.stat(assetPath, (error, stats) => {
    if (error || !stats.isFile()) {
      response.writeHead(404);
      response.end("Not found");
      return;
    }
    const contentTypes = {
      ".html": "text/html; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".svg": "image/svg+xml"
    };
    response.writeHead(200, {
      "Content-Type": contentTypes[path.extname(assetPath)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin"
    });
    fs.createReadStream(assetPath).pipe(response);
  });
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || `${HOST}:${PORT}`}`);
    const handled = await handleApi(request, response, url);
    if (handled === false) serveStatic(request, response, url);
  } catch (error) {
    if (response.headersSent || response.destroyed) return;
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status === 500) console.error(error);
    sendJson(response, status, { error: status === 500 ? "Server error. Please try again." : error.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`AR GAMES is running at http://${HOST}:${PORT}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    server.close(() => {
      database.close();
      process.exit(0);
    });
  });
}
