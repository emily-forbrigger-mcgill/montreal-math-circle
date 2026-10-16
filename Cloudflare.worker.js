
const encoder = new TextEncoder();

const SESSION_COOKIE = "__Host-mmc_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const RATE_WINDOW_SECONDS = 15 * 60;
const MAX_ATTEMPTS = 20;
const MAX_FILE_SIZE = 20 * 1024 * 1024;
const MAX_UPLOAD_REQUEST = MAX_FILE_SIZE + 1024 * 1024;

const ALLOWED_ORIGINS = new Set([
  "https://montrealmathcircle.com",
  "https://www.montrealmathcircle.com"
]);

const ALLOWED_FILE_TYPES = new Set([
  "application/pdf",
  "text/plain",
  "text/csv",
  "application/rtf",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/msword",
  "application/vnd.ms-excel",
  "application/vnd.ms-powerpoint",
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp"
]);

function json(data, status = 200, request, extraHeaders = {}) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...extraHeaders
  });
  const origin = request?.headers.get("Origin");
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return new Response(JSON.stringify(data), { status, headers });
}

function toBase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function toHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  return toHex(new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(value))
  ));
}

function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hashCode(code, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(code),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: 100000,
    hash: "SHA-256"
  }, key, 256);
  return toBase64(new Uint8Array(bits));
}

function randomHex(n) {
  return toHex(crypto.getRandomValues(new Uint8Array(n)));
}

function getCookie(request, name) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i >= 0 && part.slice(0, i).trim() === name) {
      return part.slice(i + 1).trim();
    }
  }
  return "";
}

function cookieHeader(value, maxAge) {
  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Strict`;
}

function corsPreflight(request) {
  const origin = request.headers.get("Origin") || "";
  if (!ALLOWED_ORIGINS.has(origin)) {
    return new Response(null, { status: 403 });
  }
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

async function applyLoginLimit(request, env) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || !env.ADMIN_SECRET) return false;
  const ipHash = await sha256(`${env.ADMIN_SECRET}:${ip}`);
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    "SELECT attempts, window_start FROM login_attempts WHERE ip_hash = ?"
  ).bind(ipHash).first();
  if (
    row &&
    now - row.window_start < RATE_WINDOW_SECONDS &&
    row.attempts >= MAX_ATTEMPTS
  ) {
    return false;
  }
  await env.DB.prepare(`
    INSERT INTO login_attempts (ip_hash, attempts, window_start)
    VALUES (?, 1, ?)
    ON CONFLICT(ip_hash) DO UPDATE SET
      attempts = CASE
        WHEN excluded.window_start - login_attempts.window_start >= ?
        THEN 1
        ELSE login_attempts.attempts + 1
      END,
      window_start = CASE
        WHEN excluded.window_start - login_attempts.window_start >= ?
        THEN excluded.window_start
        ELSE login_attempts.window_start
      END
  `).bind(ipHash, now, RATE_WINDOW_SECONDS, RATE_WINDOW_SECONDS).run();
  return true;
}

function validUsername(u) {
  return typeof u === "string" &&
    u.length <= 100 &&
    /^[a-z0-9]+(?:[.-][a-z0-9]+)*\.mathcircle$/.test(u);
}

function safeFilename(name) {
  if (typeof name !== "string") return "";
  name = name.normalize("NFC")
    .split(/[\\/]/)
    .pop()
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  if (!name || name === "." || name === "..") return "";
  return name.length > 180 ? name.slice(-180) : name;
}

function validFileRequestOrigin(request) {
  const origin = request.headers.get("Origin");
  return Boolean(origin && ALLOWED_ORIGINS.has(origin));
}

async function getSignedInMember(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);
  return env.DB.prepare(`
    SELECT m.id, m.name, m.username
    FROM sessions s
    JOIN members m ON m.id = s.member_id
    WHERE s.token_hash = ?
      AND s.expires_at > ?
      AND m.active = 1
  `).bind(tokenHash, now).first();
}

async function isSiteAdministrator(id, env) {
  return Boolean(await env.DB.prepare(
    "SELECT member_id FROM site_administrators WHERE member_id = ?"
  ).bind(id).first());
}

async function authorizedSiteAdministrator(request, env) {
  const member = await getSignedInMember(request, env);
  return Boolean(member && await isSiteAdministrator(member.id, env));
}

async function isFilePublisher(id, env) {
  return Boolean(
    await isSiteAdministrator(id, env) ||
    await env.DB.prepare(
      "SELECT member_id FROM file_publishers WHERE member_id = ?"
    ).bind(id).first()
  );
}

async function isFileContributor(id, env) {
  return Boolean(
    await isSiteAdministrator(id, env) ||
    await env.DB.prepare(
      "SELECT member_id FROM file_contributors WHERE member_id = ?"
    ).bind(id).first()
  );
}

function submissionSummary(row) {
  return {
    id: row.id,
    ownerUsername: row.owner_username,
    filename: row.original_filename,
    contentType: row.content_type,
    sizeBytes: row.size_bytes,
    status: row.status,
    createdAt: row.created_at,
    publishedAt: row.published_at,
    publishedByMemberId: row.published_by_member_id,
    folderId: row.folder_id ?? null
  };
}

async function readJson(request) {
  try {
    return { body: await request.json() };
  } catch {
    return { error: json({ error: "Invalid JSON" }, 400, request) };
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return corsPreflight(request);
    }

    if (path === "/" && request.method === "GET") {
      return new Response("Members portal backend is running.", {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });
    }

    if (path === "/health" && request.method === "GET") {
      try {
        const result = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM members"
        ).first();
        return json({
          worker: "ok",
          database: "ok",
          membersTable: "ok",
          memberCount: result.total
        }, 200, request);
      } catch (error) {
        console.error("Health check failed:", error);
        return json({
          worker: "ok",
          database: "not ready"
        }, 500, request);
      }
    }

    // One-time initial administrator setup.
    // Do not run again after setup has succeeded.

    if (path === "/admin/initialize-site-admin") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405, request);
      }

      const authorization = request.headers.get("Authorization") || "";
      const supplied = authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : "";

      if (
        typeof env.ADMIN_SETUP_SECRET !== "string" ||
        !env.ADMIN_SETUP_SECRET ||
        !sameSecret(supplied, env.ADMIN_SETUP_SECRET)
      ) {
        return json({ error: "Unauthorized" }, 401, request);
      }

      const parsed = await readJson(request);
      if (parsed.error) return parsed.error;

      const password = typeof parsed.body.password === "string"
        ? parsed.body.password
        : "";

      if (password.length < 8 || password.length > 256) {
        return json({
          error: "Administrator password must be 16–256 characters"
        }, 400, request);
      }

      let memberId = null;

      try {
        const existing = await env.DB.prepare(
          "SELECT member_id FROM site_administrators LIMIT 1"
        ).first();

        if (existing) {
          return json({
            error: "Site administrator setup has already been completed"
          }, 409, request);
        }

        const codeSalt = crypto.getRandomValues(new Uint8Array(16));
        const passwordSalt = crypto.getRandomValues(new Uint8Array(16));
        const unusedHash = await hashCode(randomHex(32), codeSalt);
        const passwordHash = await hashCode(password, passwordSalt);

        const inserted = await env.DB.prepare(`
          INSERT INTO members
            (name, username, code_salt, code_hash, active)
          VALUES (?, ?, ?, ?, 1)
        `).bind(
          "Main Administrator",
          "main.admin.mathcircle",
          toBase64(codeSalt),
          unusedHash
        ).run();

        memberId = inserted.meta.last_row_id;

        await env.DB.prepare(`
          INSERT INTO member_passwords
            (member_id, password_salt, password_hash)
          VALUES (?, ?, ?)
        `).bind(
          memberId,
          toHex(passwordSalt),
          passwordHash
        ).run();

        await env.DB.prepare(
          "INSERT INTO site_administrators (member_id) VALUES (?)"
        ).bind(memberId).run();

        return json({
          success: true,
          message: "Site administrator created",
          member: {
            id: memberId,
            name: "Main Administrator",
            username: "main.admin.mathcircle"
          }
        }, 201, request);
      } catch (error) {
        if (memberId !== null) {
          try {
            await env.DB.prepare(
              "DELETE FROM site_administrators WHERE member_id = ?"
            ).bind(memberId).run();

            await env.DB.prepare(
              "DELETE FROM member_passwords WHERE member_id = ?"
            ).bind(memberId).run();

            await env.DB.prepare(
              "DELETE FROM members WHERE id = ?"
            ).bind(memberId).run();
          } catch (cleanupError) {
            console.error("Admin setup cleanup failed:", cleanupError);
          }
        }

        if (String(error).includes("UNIQUE")) {
          return json({
            error: "The administrator account already exists; no new account was created"
          }, 409, request);
        }

        console.error("Initial administrator setup failed:", error);
        return json({
          error: "Could not initialize site administrator"
        }, 500, request);
      }
    }

    // Login.

    if (path === "/login") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405, request);
      }

      const parsed = await readJson(request);
      if (parsed.error) return parsed.error;

      const username = typeof parsed.body.username === "string"
        ? parsed.body.username.trim().toLowerCase()
        : "";

      const password = typeof parsed.body.password === "string"
        ? parsed.body.password
        : "";

      if (!validUsername(username) || !password || password.length > 256) {
        return json({ error: "Invalid username or password" }, 400, request);
      }

      try {
        if (!await applyLoginLimit(request, env)) {
          return json({
            error: "Too many login attempts or login rate limiting is not configured."
          }, 429, request);
        }

        const member = await env.DB.prepare(`
          SELECT id, name, username
          FROM members
          WHERE username = ? COLLATE NOCASE AND active = 1
        `).bind(username).first();

        if (!member) {
          return json({ error: "Invalid username or password" }, 401, request);
        }

        const individual = await env.DB.prepare(`
          SELECT password_salt, password_hash
          FROM member_passwords
          WHERE member_id = ?
        `).bind(member.id).first();

        let valid = false;

        if (individual && /^[a-f0-9]{32}$/i.test(individual.password_salt)) {
          const salt = new Uint8Array(
            individual.password_salt.match(/.{2}/g)
              .map(x => parseInt(x, 16))
          );

          valid = sameSecret(
            await hashCode(password, salt),
            individual.password_hash
          );
        } else if (
          !individual &&
          typeof env.SHARED_MEMBER_PASSWORD === "string" &&
          env.SHARED_MEMBER_PASSWORD.length >= 16
        ) {
          valid = sameSecret(password, env.SHARED_MEMBER_PASSWORD);
        }

        if (!valid) {
          return json({ error: "Invalid username or password" }, 401, request);
        }

        const token = randomHex(32);
        const now = Math.floor(Date.now() / 1000);
        const expires = now + SESSION_SECONDS;

        await env.DB.prepare(`
          INSERT INTO sessions (token_hash, member_id, expires_at, created_at)
          VALUES (?, ?, ?, ?)
        `).bind(
          await sha256(token),
          member.id,
          expires,
          now
        ).run();

        return json({ success: true, member }, 200, request, {
          "Set-Cookie": cookieHeader(token, SESSION_SECONDS)
        });
      } catch (error) {
        console.error("Login failed:", error);
        return json({
          error: "Login service temporarily unavailable"
        }, 500, request);
      }
    }

    // Verify the current session and return roles.

    if (path === "/me") {
      if (request.method !== "GET") {
        return json({ error: "Method not allowed" }, 405, request);
      }

      try {
        const member = await getSignedInMember(request, env);

        if (!member) {
          return json({ error: "Not signed in" }, 401, request);
        }

        const [siteAdministrator, filePublisher, fileContributor] =
          await Promise.all([
            isSiteAdministrator(member.id, env),
            isFilePublisher(member.id, env),
            isFileContributor(member.id, env)
          ]);

        return json({
          signedIn: true,
          member,
          roles: {
            siteAdministrator,
            filePublisher,
            fileContributor
          }
        }, 200, request);
      } catch (error) {
        console.error("Session check failed:", error);
        return json({
          error: "Session service temporarily unavailable"
        }, 500, request);
      }
    }

    // Logout.

    if (path === "/logout") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405, request);
      }

      try {
        const token = getCookie(request, SESSION_COOKIE);

        if (/^[a-f0-9]{64}$/.test(token)) {
          await env.DB.prepare(
            "DELETE FROM sessions WHERE token_hash = ?"
          ).bind(await sha256(token)).run();
        }

        return json({ success: true }, 200, request, {
          "Set-Cookie": cookieHeader("", 0)
        });
      } catch (error) {
        console.error("Logout failed:", error);
        return json({ error: "Could not end session" }, 500, request);
      }
    }

    // Administrator account management.

    if (path === "/admin/list-members") {
      if (request.method !== "GET") {
        return json({ error: "Method not allowed" }, 405, request);
      }

      try {
        if (!await authorizedSiteAdministrator(request, env)) {
          return json({ error: "Unauthorized" }, 401, request);
        }

        const result = await env.DB.prepare(`
          SELECT
            m.id,
            m.name,
            m.username,
            m.active,
            m.created_at AS createdAt,
            EXISTS (
              SELECT 1 FROM site_administrators sa
              WHERE sa.member_id = m.id
            ) AS siteAdministrator,
            EXISTS (
              SELECT 1 FROM file_publishers fp
              WHERE fp.member_id = m.id
            ) AS filePublisher,
            EXISTS (
              SELECT 1 FROM file_contributors fc
              WHERE fc.member_id = m.id
            ) AS fileContributor
          FROM members m
          ORDER BY m.name COLLATE NOCASE, m.id
          LIMIT 1000
        `).all();

        return json({
          success: true,
          members: result.results || []
        }, 200, request);
      } catch (error) {
        console.error("Member listing failed:", error);
        return json({
          error: "Could not list member accounts"
        }, 500, request);
      }
    }

    const adminRoutes = [
      "/admin/create-member-account",
      "/admin/set-member-active",
      "/admin/set-file-contributor",
      "/admin/set-file-publisher",
      "/admin/set-site-administrator"
    ];

    if (adminRoutes.includes(path)) {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405, request);
      }

      try {
        if (!await authorizedSiteAdministrator(request, env)) {
          return json({ error: "Unauthorized" }, 401, request);
        }
      } catch (error) {
        console.error("Administrator authorization failed:", error);
        return json({
          error: "Could not verify administrator access"
        }, 500, request);
      }

      const parsed = await readJson(request);
      if (parsed.error) return parsed.error;
      const body = parsed.body;

      // Create a member account.

      if (path === "/admin/create-member-account") {
        const name = typeof body.name === "string"
          ? body.name.trim()
          : "";

        const username = typeof body.username === "string"
          ? body.username.trim().toLowerCase()
          : "";

        const password = typeof body.password === "string"
          ? body.password
          : "";

        if (name.length < 2 || name.length > 100) {
          return json({
            error: "Name must be 2–100 characters"
          }, 400, request);
        }

        if (!validUsername(username)) {
          return json({
            error: "Use a username such as first.last.mathcircle"
          }, 400, request);
        }

        if (password.length < 12 || password.length > 256) {
          return json({
            error: "Member password must be 12–256 characters"
          }, 400, request);
        }

        let memberId = null;

        try {
          const codeSalt = crypto.getRandomValues(new Uint8Array(16));
          const codeHash = await hashCode(randomHex(32), codeSalt);

          const result = await env.DB.prepare(`
            INSERT INTO members
              (name, username, code_salt, code_hash, active)
            VALUES (?, ?, ?, ?, 1)
          `).bind(
            name,
            username,
            toBase64(codeSalt),
            codeHash
          ).run();

          memberId = result.meta.last_row_id;

          const passwordSalt = crypto.getRandomValues(
            new Uint8Array(16)
          );

          const passwordHash = await hashCode(
            password,
            passwordSalt
          );

          await env.DB.prepare(`
            INSERT INTO member_passwords
              (member_id, password_salt, password_hash)
            VALUES (?, ?, ?)
          `).bind(
            memberId,
            toHex(passwordSalt),
            passwordHash
          ).run();

          return json({
            success: true,
            memberId,
            name,
            username
          }, 201, request);
        } catch (error) {
          if (memberId !== null) {
            try {
              await env.DB.prepare(
                "DELETE FROM member_passwords WHERE member_id = ?"
              ).bind(memberId).run();

              await env.DB.prepare(
                "DELETE FROM members WHERE id = ?"
              ).bind(memberId).run();
            } catch (cleanupError) {
              console.error(
                "Member creation cleanup failed:",
                cleanupError
              );
            }
          }

          if (String(error).includes("UNIQUE")) {
            return json({
              error: "That member name or username already exists"
            }, 409, request);
          }

          console.error("Member creation failed:", error);
          return json({
            error: "Could not create member account"
          }, 500, request);
        }
      }

      const username = typeof body.username === "string"
        ? body.username.trim().toLowerCase()
        : "";

      if (!validUsername(username)) {
        return json({ error: "Provide a valid username" }, 400, request);
      }

      const target = await env.DB.prepare(`
        SELECT id, username, active
        FROM members
        WHERE username = ? COLLATE NOCASE
      `).bind(username).first();

      if (!target) {
        return json({ error: "Member not found" }, 404, request);
      }

      // Activate or deactivate an account.

      if (path === "/admin/set-member-active") {
        if (typeof body.active !== "boolean") {
          return json({
            error: "Provide active: true or false"
          }, 400, request);
        }

        if (!body.active && await isSiteAdministrator(target.id, env)) {
          const count = await env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM site_administrators sa
            JOIN members m ON m.id = sa.member_id
            WHERE m.active = 1
          `).first();

          if (count.total <= 1) {
            return json({
              error: "Cannot deactivate the last active site administrator"
            }, 409, request);
          }
        }

        await env.DB.prepare(
          "UPDATE members SET active = ? WHERE id = ?"
        ).bind(body.active ? 1 : 0, target.id).run();

        if (!body.active) {
          await env.DB.prepare(
            "DELETE FROM sessions WHERE member_id = ?"
          ).bind(target.id).run();
        }

        return json({
          success: true,
          username: target.username,
          active: body.active
        }, 200, request);
      }

      if (target.active !== 1) {
        return json({ error: "Active member not found" }, 404, request);
      }

      // Grant or revoke contributor or publisher permissions.

      if (
        path === "/admin/set-file-contributor" ||
        path === "/admin/set-file-publisher"
      ) {
        const field = path.endsWith("contributor")
          ? "contributor"
          : "publisher";

        if (typeof body[field] !== "boolean") {
          return json({
            error: `Provide ${field}: true or false`
          }, 400, request);
        }

        const table = field === "contributor"
          ? "file_contributors"
          : "file_publishers";

        if (body[field]) {
          await env.DB.prepare(
            `INSERT OR IGNORE INTO ${table} (member_id) VALUES (?)`
          ).bind(target.id).run();
        } else {
          await env.DB.prepare(
            `DELETE FROM ${table} WHERE member_id = ?`
          ).bind(target.id).run();
        }

        return json({
          success: true,
          username: target.username,
          [field]: body[field]
        }, 200, request);
      }

      // Grant or revoke site-administrator permissions.

      if (typeof body.administrator !== "boolean") {
        return json({
          error: "Provide administrator: true or false"
        }, 400, request);
      }

      if (body.administrator) {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO site_administrators (member_id)
          VALUES (?)
        `).bind(target.id).run();
      } else {
        if (await isSiteAdministrator(target.id, env)) {
          const count = await env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM site_administrators sa
            JOIN members m ON m.id = sa.member_id
            WHERE m.active = 1
          `).first();

          if (count.total <= 1) {
            return json({
              error: "Cannot remove the last active site administrator"
            }, 409, request);
          }
        }

        await env.DB.prepare(
          "DELETE FROM site_administrators WHERE member_id = ?"
        ).bind(target.id).run();
      }

      return json({
        success: true,
        username: target.username,
        administrator: body.administrator
      }, 200, request);
    }

    // File routes require an active signed-in member.
    
    // IMPORTANT LINKS
    // All signed-in members can view links.
    // Only site administrators can manage links.

    if (
      path === "/important-links" ||
      path.startsWith("/important-links/")
    ) {
      if (
        ["POST", "DELETE"].includes(request.method) &&
        !validFileRequestOrigin(request)
      ) {
        return json(
          { error: "Invalid request origin" },
          403,
          request
        );
      }

      let member;

      try {
        member = await getSignedInMember(request, env);
      } catch (error) {
        console.error("Important links session error:", error);
        return json(
          { error: "Could not verify session" },
          500,
          request
        );
      }

      if (!member) {
        return json(
          { error: "Sign in required" },
          401,
          request
        );
      }

      // View links: all signed-in members.
      if (
        path === "/important-links" &&
        request.method === "GET"
      ) {
        try {
          const result = await env.DB.prepare(`
            SELECT
              id,
              title,
              url,
              description,
              sort_order AS sortOrder
            FROM important_links
            ORDER BY sort_order ASC, id ASC
          `).all();

          return json(
            { links: result.results || [] },
            200,
            request
          );
        } catch (error) {
          console.error("Important links listing failed:", error);
          return json(
            { error: "Could not load important links" },
            500,
            request
          );
        }
      }

      if (!["POST", "DELETE"].includes(request.method)) {
        return json(
          { error: "Method not allowed" },
          405,
          request
        );
      }

      // All management actions require administrator access.
      try {
        if (!await isSiteAdministrator(member.id, env)) {
          return json(
            { error: "Administrator permission required" },
            403,
            request
          );
        }
      } catch (error) {
        console.error("Important links permission error:", error);
        return json(
          { error: "Could not verify permissions" },
          500,
          request
        );
      }

      // Reorder links.
      if (
        path === "/important-links/reorder" &&
        request.method === "POST"
      ) {
        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const ids = parsed.body?.ids;

        if (
          !Array.isArray(ids) ||
          !ids.every(id => Number.isSafeInteger(id) && id > 0) ||
          new Set(ids).size !== ids.length ||
          ids.length > 500
        ) {
          return json(
            { error: "Provide an array of unique link IDs" },
            400,
            request
          );
        }

        try {
          const existing = await env.DB.prepare(
            "SELECT id FROM important_links"
          ).all();

          const stored = (existing.results || []).map(
            row => row.id
          );

          if (
            stored.length !== ids.length ||
            stored.some(id => !ids.includes(id))
          ) {
            return json(
              {
                error: "Link list changed; refresh and try again"
              },
              409,
              request
            );
          }

          if (ids.length) {
            await env.DB.batch(
              ids.map((id, index) =>
                env.DB.prepare(`
                  UPDATE important_links
                  SET sort_order = ?
                  WHERE id = ?
                `).bind(index, id)
              )
            );
          }

          return json({ success: true }, 200, request);
        } catch (error) {
          console.error("Important links reorder failed:", error);
          return json(
            { error: "Could not reorder links" },
            500,
            request
          );
        }
      }

      const linkRoute = path.match(
        /^\/important-links\/([0-9]+)$/
      );

      // Delete a link.
      if (request.method === "DELETE" && linkRoute) {
        try {
          const result = await env.DB.prepare(`
            DELETE FROM important_links
            WHERE id = ?
          `).bind(Number(linkRoute[1])).run();

          if (!result.meta.changes) {
            return json(
              { error: "Link not found" },
              404,
              request
            );
          }

          return json({ success: true }, 200, request);
        } catch (error) {
          console.error("Important link deletion failed:", error);
          return json(
            { error: "Could not delete link" },
            500,
            request
          );
        }
      }

      // Create or edit a link.
      if (
        request.method === "POST" &&
        (path === "/important-links" || linkRoute)
      ) {
        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const body = parsed.body || {};

        const title =
          typeof body.title === "string"
            ? body.title.trim()
            : "";

        const address =
          typeof body.url === "string"
            ? body.url.trim()
            : "";

        const description =
          typeof body.description === "string"
            ? body.description.trim()
            : "";

        if (
          !title ||
          title.length > 120 ||
          /[\x00-\x1f\x7f]/.test(title) ||
          !address ||
          address.length > 2048 ||
          description.length > 300 ||
          /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(description)
        ) {
          return json(
            {
              error: "Invalid title, URL, or description"
            },
            400,
            request
          );
        }

        let parsedUrl;

        try {
          parsedUrl = new URL(address);
        } catch {
          // Invalid URLs are rejected below.
        }

        if (
          !parsedUrl ||
          !["https:", "http:"].includes(parsedUrl.protocol) ||
          !parsedUrl.hostname ||
          parsedUrl.username ||
          parsedUrl.password
        ) {
          return json(
            { error: "Provide a valid http or https URL" },
            400,
            request
          );
        }

        try {
          // Update existing link.
          if (linkRoute) {
            const result = await env.DB.prepare(`
              UPDATE important_links
              SET title = ?, url = ?, description = ?
              WHERE id = ?
            `).bind(
              title,
              address,
              description,
              Number(linkRoute[1])
            ).run();

            if (!result.meta.changes) {
              return json(
                { error: "Link not found" },
                404,
                request
              );
            }

            return json({ success: true }, 200, request);
          }

          // Add new link at the end of the list.
          const result = await env.DB.prepare(`
            INSERT INTO important_links
              (title, url, description, sort_order)
            VALUES (
              ?, ?, ?,
              (
                SELECT COALESCE(MAX(sort_order), -1) + 1
                FROM important_links
              )
            )
          `).bind(
            title,
            address,
            description
          ).run();

          return json(
            {
              success: true,
              link: { id: result.meta.last_row_id }
            },
            201,
            request
          );
        } catch (error) {
          console.error("Important link save failed:", error);
          return json(
            { error: "Could not save link" },
            500,
            request
          );
        }
      }

      return json(
        { error: "Important links route not found" },
        404,
        request
      );
    }

  
    // MEMBER DIRECTORY
    // Signed-in members can view.
    // Only site administrators can manage entries.

    if (
      path === "/member-directory" ||
      path.startsWith("/member-directory/")
    ) {
      if (
        ["POST", "DELETE"].includes(request.method) &&
        !validFileRequestOrigin(request)
      ) {
        return json({ error: "Invalid request origin" }, 403, request);
      }

      let member;

      try {
        member = await getSignedInMember(request, env);
      } catch (error) {
        console.error("Directory session error:", error);
        return json({ error: "Could not verify session" }, 500, request);
      }

      if (!member) {
        return json({ error: "Sign in required" }, 401, request);
      }

      // View the directory.
      if (path === "/member-directory" && request.method === "GET") {
        try {
          const result = await env.DB.prepare(`
            SELECT
              id,
              full_name AS fullName,
              member_role AS memberRole,
              email,
              phone,
              description,
              sort_order AS sortOrder
            FROM member_directory
            ORDER BY sort_order ASC, id ASC
          `).all();

          return json(
            { members: result.results || [] },
            200,
            request
          );
        } catch (error) {
          console.error("Directory listing error:", error);
          return json(
            { error: "Could not load member directory" },
            500,
            request
          );
        }
      }

      if (!["POST", "DELETE"].includes(request.method)) {
        return json({ error: "Method not allowed" }, 405, request);
      }

      // All changes require administrator permission.
      try {
        if (!await isSiteAdministrator(member.id, env)) {
          return json(
            { error: "Administrator permission required" },
            403,
            request
          );
        }
      } catch (error) {
        console.error("Directory permission error:", error);
        return json(
          { error: "Could not verify permissions" },
          500,
          request
        );
      }

      // Change the order of entries.
      if (
        path === "/member-directory/reorder" &&
        request.method === "POST"
      ) {
        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const ids = parsed.body?.ids;

        if (
          !Array.isArray(ids) ||
          ids.length > 500 ||
          !ids.every(id => Number.isSafeInteger(id) && id > 0) ||
          new Set(ids).size !== ids.length
        ) {
          return json(
            { error: "Invalid directory entry IDs" },
            400,
            request
          );
        }

        try {
          const existing = await env.DB.prepare(
            "SELECT id FROM member_directory"
          ).all();

          const stored = (existing.results || []).map(row => row.id);

          if (
            stored.length !== ids.length ||
            stored.some(id => !ids.includes(id))
          ) {
            return json(
              { error: "Directory changed; refresh and try again" },
              409,
              request
            );
          }

          if (ids.length) {
            await env.DB.batch(
              ids.map((id, index) =>
                env.DB.prepare(`
                  UPDATE member_directory
                  SET sort_order = ?
                  WHERE id = ?
                `).bind(index, id)
              )
            );
          }

          return json({ success: true }, 200, request);
        } catch (error) {
          console.error("Directory reorder error:", error);
          return json(
            { error: "Could not reorder directory" },
            500,
            request
          );
        }
      }

      const match = path.match(/^\/member-directory\/([0-9]+)$/);

      // Delete an entry.
      if (request.method === "DELETE" && match) {
        try {
          const result = await env.DB.prepare(`
            DELETE FROM member_directory WHERE id = ?
          `).bind(Number(match[1])).run();

          if (!result.meta.changes) {
            return json(
              { error: "Directory entry not found" },
              404,
              request
            );
          }

          return json({ success: true }, 200, request);
        } catch (error) {
          console.error("Directory deletion error:", error);
          return json(
            { error: "Could not delete directory entry" },
            500,
            request
          );
        }
      }

      // Create or edit an entry.
      if (
        request.method === "POST" &&
        (path === "/member-directory" || match)
      ) {
        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const body = parsed.body || {};

        const fields = [
          ["fullName", 120],
          ["memberRole", 120],
          ["email", 254],
          ["phone", 60],
          ["description", 500]
        ];

        const values = {};

        for (const [field, maxLength] of fields) {
          if (
            body[field] !== undefined &&
            typeof body[field] !== "string"
          ) {
            return json(
              { error: `Invalid ${field}` },
              400,
              request
            );
          }

          values[field] = (body[field] || "").trim();

          if (
            values[field].length > maxLength ||
            /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(values[field])
          ) {
            return json(
              { error: `Invalid ${field}` },
              400,
              request
            );
          }
        }

        if (!values.fullName) {
          return json(
            { error: "Full name is required" },
            400,
            request
          );
        }

        if (
          values.email &&
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)
        ) {
          return json(
            { error: "Enter a valid email address" },
            400,
            request
          );
        }

        try {
          const parameters = [
            values.fullName,
            values.memberRole,
            values.email,
            values.phone,
            values.description
          ];

          if (match) {
            const result = await env.DB.prepare(`
              UPDATE member_directory
              SET full_name = ?,
                  member_role = ?,
                  email = ?,
                  phone = ?,
                  description = ?
              WHERE id = ?
            `).bind(...parameters, Number(match[1])).run();

            if (!result.meta.changes) {
              return json(
                { error: "Directory entry not found" },
                404,
                request
              );
            }

            return json({ success: true }, 200, request);
          }

          const result = await env.DB.prepare(`
            INSERT INTO member_directory
              (full_name, member_role, email, phone,
               description, sort_order)
            VALUES (
              ?, ?, ?, ?, ?,
              (SELECT COALESCE(MAX(sort_order), -1) + 1
               FROM member_directory)
            )
          `).bind(...parameters).run();

          return json(
            {
              success: true,
              member: { id: result.meta.last_row_id }
            },
            201,
            request
          );
        } catch (error) {
          console.error("Directory save error:", error);
          return json(
            { error: "Could not save directory entry" },
            500,
            request
          );
        }
      }

      return json(
        { error: "Member directory route not found" },
        404,
        request
      );
    }
    
    // MEMBERS CALENDAR
    // Members can view events; site administrators manage them.

    if (
      path === "/calendar-events" ||
      path.startsWith("/calendar-events/")
    ) {
      if (
        ["POST", "DELETE"].includes(request.method) &&
        !validFileRequestOrigin(request)
      ) {
        return json({ error: "Invalid request origin" }, 403, request);
      }

      let member;

      try {
        member = await getSignedInMember(request, env);
      } catch (error) {
        console.error("Calendar authentication error:", error);
        return json({ error: "Could not verify session" }, 500, request);
      }

      if (!member) {
        return json({ error: "Sign in required" }, 401, request);
      }

      // Get all calendar events.
      if (path === "/calendar-events" && request.method === "GET") {
        try {
          const result = await env.DB.prepare(`
            SELECT
              id,
              title,
              event_date AS eventDate,
              start_time AS startTime,
              end_time AS endTime,
              location,
              description
            FROM calendar_events
            ORDER BY event_date ASC, start_time ASC, id ASC
          `).all();

          return json(
            { events: result.results || [] },
            200,
            request
          );
        } catch (error) {
          console.error("Calendar loading error:", error);
          return json(
            { error: "Could not load calendar events" },
            500,
            request
          );
        }
      }

      if (!["POST", "DELETE"].includes(request.method)) {
        return json({ error: "Method not allowed" }, 405, request);
      }

     
      // Publishers and site administrators may manage calendar events.
      try {
        if (!await isFilePublisher(member.id, env)) {
          return json(
            { error: "Publisher permission required" },
            403,
            request
          );
        }
      } catch (error) {
        console.error("Calendar permission error:", error);
        return json(
          { error: "Could not verify publisher permissions" },
          500,
          request
        );
      }




      const match = path.match(/^\/calendar-events\/([0-9]+)$/);

      // Delete an event.
      if (request.method === "DELETE" && match) {
        try {
          const result = await env.DB.prepare(`
            DELETE FROM calendar_events
            WHERE id = ?
          `).bind(Number(match[1])).run();

          if (!result.meta.changes) {
            return json({ error: "Event not found" }, 404, request);
          }

          return json({ success: true }, 200, request);
        } catch (error) {
          console.error("Calendar deletion error:", error);
          return json(
            { error: "Could not delete calendar event" },
            500,
            request
          );
        }
      }

      // Add or edit an event.
      if (
        request.method === "POST" &&
        (path === "/calendar-events" || match)
      ) {
        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const body = parsed.body || {};

        const limits = {
          title: 150,
          eventDate: 10,
          startTime: 5,
          endTime: 5,
          location: 200,
          description: 2000
        };

        const values = {};

        for (const [field, limit] of Object.entries(limits)) {
          if (
            body[field] !== undefined &&
            typeof body[field] !== "string"
          ) {
            return json(
              { error: `Invalid ${field}` },
              400,
              request
            );
          }

          values[field] = (body[field] || "").trim();

          if (
            values[field].length > limit ||
            /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(values[field])
          ) {
            return json(
              { error: `Invalid ${field}` },
              400,
              request
            );
          }
        }

        if (!values.title) {
          return json(
            { error: "Event title is required" },
            400,
            request
          );
        }

        const validDate = /^\d{4}-\d{2}-\d{2}$/.test(values.eventDate);
        const parsedDate = new Date(values.eventDate + "T12:00:00Z");

        if (
          !validDate ||
          Number.isNaN(parsedDate.getTime()) ||
          parsedDate.toISOString().slice(0, 10) !== values.eventDate
        ) {
          return json(
            { error: "Enter a valid event date" },
            400,
            request
          );
        }

        const timePattern = /^([01]\d|2[0-3]):[0-5]\d$/;

        if (
          (values.startTime && !timePattern.test(values.startTime)) ||
          (values.endTime && !timePattern.test(values.endTime))
        ) {
          return json(
            { error: "Times must use HH:MM format" },
            400,
            request
          );
        }

        if (
          values.endTime &&
          !values.startTime
        ) {
          return json(
            { error: "Enter a start time before an end time" },
            400,
            request
          );
        }

        if (
          values.startTime &&
          values.endTime &&
          values.endTime <= values.startTime
        ) {
          return json(
            { error: "End time must be after start time" },
            400,
            request
          );
        }

        const params = [
          values.title,
          values.eventDate,
          values.startTime,
          values.endTime,
          values.location,
          values.description
        ];

        try {
          if (match) {
            const result = await env.DB.prepare(`
              UPDATE calendar_events
              SET title = ?,
                  event_date = ?,
                  start_time = ?,
                  end_time = ?,
                  location = ?,
                  description = ?
              WHERE id = ?
            `).bind(...params, Number(match[1])).run();

            if (!result.meta.changes) {
              return json({ error: "Event not found" }, 404, request);
            }

            return json({ success: true }, 200, request);
          }

          const result = await env.DB.prepare(`
            INSERT INTO calendar_events
              (title, event_date, start_time,
               end_time, location, description)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(...params).run();

          return json(
            {
              success: true,
              event: { id: result.meta.last_row_id }
            },
            201,
            request
          );
        } catch (error) {
          console.error("Calendar saving error:", error);
          return json(
            { error: "Could not save calendar event" },
            500,
            request
          );
        }
      }

      return json(
        { error: "Calendar route not found" },
        404,
        request
      );
    }
    
    // MEMBERS DISCUSSION BOARD
    // Only signed-in members can access discussions.

    if (
      path === "/discussion/topics" ||
      path.startsWith("/discussion/topics/")
    ) {
      // Protect requests that change data.
      if (
        ["POST", "DELETE"].includes(request.method) &&
        !validFileRequestOrigin(request)
      ) {
        return json(
          { error: "Invalid request origin" },
          403,
          request
        );
      }

      let member;

      try {
        member = await getSignedInMember(request, env);
      } catch (error) {
        console.error("Discussion authentication error:", error);
        return json(
          { error: "Could not verify your session" },
          500,
          request
        );
      }

      if (!member) {
        return json(
          { error: "Sign in required" },
          401,
          request
        );
      }

      // List discussions, newest activity first.
      if (
        path === "/discussion/topics" &&
        request.method === "GET"
      ) {
        try {
          const result = await env.DB.prepare(`
            SELECT
              t.id,
              t.title,
              t.body,
              t.author_id AS authorId,
              m.name AS authorName,
              t.is_pinned AS isPinned,
              t.is_locked AS isLocked,
              t.created_at AS createdAt,
              t.updated_at AS updatedAt,
              (
                SELECT COUNT(*)
                FROM discussion_replies r
                WHERE r.topic_id = t.id
              ) AS replyCount
            FROM discussion_topics t
            JOIN members m ON m.id = t.author_id
            ORDER BY
              t.is_pinned DESC,
              t.updated_at DESC,
              t.id DESC
            LIMIT 200
          `).all();

          return json(
            { topics: result.results || [] },
            200,
            request
          );
        } catch (error) {
          console.error("Discussion listing error:", error);
          return json(
            { error: "Could not load discussions" },
            500,
            request
          );
        }
      }

      // Create a new discussion topic.
      if (
        path === "/discussion/topics" &&
        request.method === "POST"
      ) {
        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const body = parsed.body || {};

        if (
          typeof body.title !== "string" ||
          typeof body.body !== "string"
        ) {
          return json(
            { error: "Title and message are required" },
            400,
            request
          );
        }

        const title = body.title.trim();
        const message = body.body.trim();

        if (
          title.length < 3 ||
          title.length > 150 ||
          message.length < 1 ||
          message.length > 10000
        ) {
          return json(
            {
              error:
                "Title must be 3–150 characters and message 1–10000 characters"
            },
            400,
            request
          );
        }

        try {
          // Limit each member to one new topic per minute.
          const recent = await env.DB.prepare(`
            SELECT id
            FROM discussion_topics
            WHERE author_id = ?
              AND created_at >= datetime('now', '-1 minute')
            LIMIT 1
          `).bind(member.id).first();

          if (recent) {
            return json(
              { error: "Please wait a minute before starting another topic" },
              429,
              request
            );
          }

          const result = await env.DB.prepare(`
            INSERT INTO discussion_topics
              (author_id, title, body)
            VALUES (?, ?, ?)
          `).bind(
            member.id,
            title,
            message
          ).run();

          return json(
            {
              success: true,
              topic: { id: result.meta.last_row_id }
            },
            201,
            request
          );
        } catch (error) {
          console.error("Discussion creation error:", error);
          return json(
            { error: "Could not create discussion" },
            500,
            request
          );
        }
      }
      
      // DISCUSSION MODERATION
      // Administrators manage topics.
      // Members may delete their own replies.

      const moderateMatch = path.match(
        /^\/discussion\/topics\/([0-9]+)\/moderate$/
      );

      // Pin, unpin, lock, or unlock a discussion.
      if (moderateMatch && request.method === "POST") {
        const isAdmin = await isSiteAdministrator(member.id, env);

        if (!isAdmin) {
          return json(
            { error: "Administrator permission required" },
            403,
            request
          );
        }

        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const action = parsed.body?.action;
        const allowed = ["pin", "unpin", "lock", "unlock"];

        if (!allowed.includes(action)) {
          return json(
            { error: "Invalid moderation action" },
            400,
            request
          );
        }

        const topicId = Number(moderateMatch[1]);

        try {
          let result;

          if (action === "pin" || action === "unpin") {
            result = await env.DB.prepare(`
              UPDATE discussion_topics
              SET is_pinned = ?
              WHERE id = ?
            `).bind(action === "pin" ? 1 : 0, topicId).run();
          } else {
            result = await env.DB.prepare(`
              UPDATE discussion_topics
              SET is_locked = ?
              WHERE id = ?
            `).bind(action === "lock" ? 1 : 0, topicId).run();
          }

          if (!result.meta.changes) {
            return json(
              { error: "Discussion not found" },
              404,
              request
            );
          }

          return json({ success: true }, 200, request);
        } catch (error) {
          console.error("Discussion moderation error:", error);
          return json(
            { error: "Could not update discussion" },
            500,
            request
          );
        }
      }

      // Delete an entire discussion and its replies.
      const deleteTopicMatch = path.match(
        /^\/discussion\/topics\/([0-9]+)$/
      );

      if (deleteTopicMatch && request.method === "DELETE") {
        const isAdmin = await isSiteAdministrator(member.id, env);

        if (!isAdmin) {
          return json(
            { error: "Administrator permission required" },
            403,
            request
          );
        }

        const topicId = Number(deleteTopicMatch[1]);

        try {
          const existing = await env.DB.prepare(`
            SELECT id
            FROM discussion_topics
            WHERE id = ?
          `).bind(topicId).first();

          if (!existing) {
            return json(
              { error: "Discussion not found" },
              404,
              request
            );
          }

          // D1 batch applies both deletions transactionally.
          await env.DB.batch([
            env.DB.prepare(`
              DELETE FROM discussion_replies
              WHERE topic_id = ?
            `).bind(topicId),

            env.DB.prepare(`
              DELETE FROM discussion_topics
              WHERE id = ?
            `).bind(topicId)
          ]);

          return json({ success: true }, 200, request);
        } catch (error) {
          console.error("Discussion deletion error:", error);
          return json(
            { error: "Could not delete discussion" },
            500,
            request
          );
        }
      }

      // Delete a reply.
      // Reply authors can delete their own replies.
      // Site administrators can delete any reply.

      const deleteReplyMatch = path.match(
        /^\/discussion\/topics\/([0-9]+)\/replies\/([0-9]+)$/
      );

      if (deleteReplyMatch && request.method === "DELETE") {
        const topicId = Number(deleteReplyMatch[1]);
        const replyId = Number(deleteReplyMatch[2]);

        try {
          const reply = await env.DB.prepare(`
            SELECT id, author_id AS authorId
            FROM discussion_replies
            WHERE id = ? AND topic_id = ?
          `).bind(replyId, topicId).first();

          if (!reply) {
            return json(
              { error: "Reply not found" },
              404,
              request
            );
          }

          const isAuthor =
            Number(reply.authorId) === Number(member.id);

          const isAdmin = await isSiteAdministrator(member.id, env);

          if (!isAuthor && !isAdmin) {
            return json(
              { error: "You cannot delete this reply" },
              403,
              request
            );
          }

          await env.DB.prepare(`
            DELETE FROM discussion_replies
            WHERE id = ? AND topic_id = ?
          `).bind(replyId, topicId).run();

          return json({ success: true }, 200, request);
        } catch (error) {
          console.error("Reply deletion error:", error);
          return json(
            { error: "Could not delete reply" },
            500,
            request
          );
        }
      }
     
  // VIEW ONE DISCUSSION AND ITS REPLIES

      const discussionMatch = path.match(
        /^\/discussion\/topics\/([0-9]+)$/
      );

      if (discussionMatch && request.method === "GET") {
        const topicId = Number(discussionMatch[1]);

        try {
          const topic = await env.DB.prepare(`
            SELECT
              t.id,
              t.title,
              t.body,
              t.author_id AS authorId,
              m.name AS authorName,
              t.is_pinned AS isPinned,
              t.is_locked AS isLocked,
              t.created_at AS createdAt,
              t.updated_at AS updatedAt
            FROM discussion_topics t
            JOIN members m ON m.id = t.author_id
            WHERE t.id = ?
          `).bind(topicId).first();

          if (!topic) {
            return json(
              { error: "Discussion not found" },
              404,
              request
            );
          }

          const result = await env.DB.prepare(`
            SELECT
              r.id,
              r.topic_id AS topicId,
              r.author_id AS authorId,
              m.name AS authorName,
              r.body,
              r.created_at AS createdAt,
              r.updated_at AS updatedAt
            FROM discussion_replies r
            JOIN members m ON m.id = r.author_id
            WHERE r.topic_id = ?
            ORDER BY r.created_at ASC, r.id ASC
            LIMIT 500
          `).bind(topicId).all();

          return json(
            {
              topic,
              replies: result.results || []
            },
            200,
            request
          );
        } catch (error) {
          console.error("Discussion loading error:", error);

          return json(
            { error: "Could not load discussion" },
            500,
            request
          );
        }
      }

    
      
  // POST A REPLY TO A DISCUSSION

      const replyMatch = path.match(
        /^\/discussion\/topics\/([0-9]+)\/replies$/
      );

      if (replyMatch && request.method === "POST") {
        const topicId = Number(replyMatch[1]);

        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const body = parsed.body || {};

        if (typeof body.body !== "string") {
          return json(
            { error: "Reply text is required" },
            400,
            request
          );
        }

        const message = body.body.trim();

        if (message.length < 1 || message.length > 10000) {
          return json(
            { error: "Reply must contain 1–10000 characters" },
            400,
            request
          );
        }

        try {
          const topic = await env.DB.prepare(`
            SELECT id, is_locked AS isLocked
            FROM discussion_topics
            WHERE id = ?
          `).bind(topicId).first();

          if (!topic) {
            return json(
              { error: "Discussion not found" },
              404,
              request
            );
          }

          if (topic.isLocked) {
            return json(
              { error: "This discussion is closed to new replies" },
              403,
              request
            );
          }

          // Basic spam prevention:
          // one reply per member every 15 seconds.

          const recent = await env.DB.prepare(`
            SELECT id
            FROM discussion_replies
            WHERE author_id = ?
              AND created_at >= datetime('now', '-15 seconds')
            LIMIT 1
          `).bind(member.id).first();

          if (recent) {
            return json(
              { error: "Please wait 15 seconds before replying again" },
              429,
              request
            );
          }

          const results = await env.DB.batch([
            env.DB.prepare(`
              INSERT INTO discussion_replies
                (topic_id, author_id, body)
              VALUES (?, ?, ?)
            `).bind(
              topicId,
              member.id,
              message
            ),

            env.DB.prepare(`
              UPDATE discussion_topics
              SET updated_at = CURRENT_TIMESTAMP
              WHERE id = ?
                AND is_locked = 0
            `).bind(topicId)
          ]);

          if (!results[1]?.meta?.changes) {
            return json(
              { error: "Discussion is no longer open" },
              409,
              request
            );
          }

          return json(
            {
              success: true,
              reply: {
                id: results[0].meta.last_row_id
              }
            },
            201,
            request
          );
        } catch (error) {
          console.error("Discussion reply error:", error);

          return json(
            { error: "Could not post reply" },
            500,
            request
          );
        }
      }


      return json(
        { error: "Discussion route not found" },
        404,
        request
      );
    }

    


    if (path.startsWith("/files/")) {
      if (
        ["POST", "DELETE"].includes(request.method) &&
        !validFileRequestOrigin(request)
      ) {
        return json({
          error: "Invalid request origin"
        }, 403, request);
      }

      let member;

      try {
        member = await getSignedInMember(request, env);
      } catch (error) {
        console.error("File session check failed:", error);
        return json({
          error: "Could not verify session"
        }, 500, request);
      }

      if (!member) {
        return json({
          error: "Sign in required"
        }, 401, request);
      }

      let publisher;
      let contributor;

      try {
        publisher = await isFilePublisher(member.id, env);
        contributor = await isFileContributor(member.id, env);
      } catch (error) {
        console.error("File permission check failed:", error);
        return json({
          error: "Could not verify permissions"
        }, 500, request);
      }

      // FOLDER SYSTEM
      // Members can view folders.
      // Only administrators can manage folders.

      if (path === "/files/folders" && request.method === "GET") {
        try {
          const result = await env.DB.prepare(`
            SELECT
              f.id,
              f.name,
              f.created_at AS createdAt,
              (
                SELECT COUNT(*)
                FROM file_submissions s
                WHERE s.folder_id = f.id
                  AND s.status = 'published'
              ) AS fileCount
            FROM file_folders f
            ORDER BY f.name COLLATE NOCASE, f.id
          `).all();

          return json({
            folders: result.results || []
          }, 200, request);
        } catch (error) {
          console.error("Folder listing failed:", error);
          return json({
            error: "Could not load folders"
          }, 500, request);
        }
      }

      // Create folder.

      if (path === "/files/folders" && request.method === "POST") {
        if (!await isSiteAdministrator(member.id, env)) {
          return json({
            error: "Administrator permission required"
          }, 403, request);
        }

        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const name = typeof parsed.body.name === "string"
          ? parsed.body.name.trim()
          : "";

        if (
          !name ||
          name.length > 80 ||
          /[\u0000-\u001f\u007f]/.test(name)
        ) {
          return json({
            error: "Folder name must be 1–80 characters"
          }, 400, request);
        }

        try {
          const result = await env.DB.prepare(
            "INSERT INTO file_folders (name) VALUES (?)"
          ).bind(name).run();

          return json({
            success: true,
            folder: {
              id: result.meta.last_row_id,
              name
            }
          }, 201, request);
        } catch (error) {
          if (String(error).includes("UNIQUE")) {
            return json({
              error: "A folder with that name already exists"
            }, 409, request);
          }

          console.error("Folder creation failed:", error);
          return json({
            error: "Could not create folder"
          }, 500, request);
        }
      }

      // Rename or delete folder.

      const folderRoute = path.match(
        /^\/files\/folders\/([0-9]+)$/
      );

      if (
        folderRoute &&
        ["POST", "DELETE"].includes(request.method)
      ) {
        if (!await isSiteAdministrator(member.id, env)) {
          return json({
            error: "Administrator permission required"
          }, 403, request);
        }

        const folderId = Number(folderRoute[1]);

        try {
          const folder = await env.DB.prepare(
            "SELECT id FROM file_folders WHERE id = ?"
          ).bind(folderId).first();

          if (!folder) {

      
    

            return json({
              error: "Folder not found"
            }, 404, request);
          }

          if (request.method === "DELETE") {
            // Preserve documents when their folder is removed.
            await env.DB.batch([
              env.DB.prepare(`
                UPDATE file_submissions
                SET folder_id = NULL
                WHERE folder_id = ?
              `).bind(folderId),
              env.DB.prepare(`
                DELETE FROM file_folders
                WHERE id = ?
              `).bind(folderId)
            ]);

            return json({
              success: true
            }, 200, request);
          }

          const parsed = await readJson(request);
          if (parsed.error) return parsed.error;

          const name = typeof parsed.body.name === "string"
            ? parsed.body.name.trim()
            : "";

          if (
            !name ||
            name.length > 80 ||
            /[\u0000-\u001f\u007f]/.test(name)
          ) {
            return json({
              error: "Folder name must be 1–80 characters"
            }, 400, request);
          }

          await env.DB.prepare(`
            UPDATE file_folders
            SET name = ?
            WHERE id = ?
          `).bind(name, folderId).run();

          return json({
            success: true
          }, 200, request);
        } catch (error) {
          if (String(error).includes("UNIQUE")) {
            return json({
              error: "A folder with that name already exists"
            }, 409, request);
          }

          console.error("Folder update failed:", error);
          return json({
            error: "Could not update folder"
          }, 500, request);
        }
      }

      // Assign published document to folder.
      // null = Unfiled.

      const moveFile = path.match(
        /^\/files\/submissions\/([0-9]+)\/folder$/
      );

      if (moveFile && request.method === "POST") {
        if (!await isSiteAdministrator(member.id, env)) {
          return json({
            error: "Administrator permission required"
          }, 403, request);
        }

        const parsed = await readJson(request);
        if (parsed.error) return parsed.error;

        const folderId = parsed.body.folderId;

        if (
          folderId !== null &&
          (!Number.isSafeInteger(folderId) || folderId < 1)
        ) {
          return json({
            error: "Use a valid folderId or null for Unfiled"
          }, 400, request);
        }

        try {
          if (folderId !== null) {
            const folder = await env.DB.prepare(
              "SELECT id FROM file_folders WHERE id = ?"
            ).bind(folderId).first();

            if (!folder) {
              return json({
                error: "Folder not found"
              }, 404, request);
            }
          }

          const result = await env.DB.prepare(`
            UPDATE file_submissions
            SET folder_id = ?
            WHERE id = ?
              AND status = 'published'
          `).bind(folderId, Number(moveFile[1])).run();

          if (!result.meta.changes) {
            return json({
              error: "Published document not found"
            }, 404, request);
          }

          return json({
            success: true
          }, 200, request);
        } catch (error) {
          console.error("Moving file failed:", error);
          return json({
            error: "Could not move document"
          }, 500, request);
        }
      }

      // List published files and submissions.

      if (path === "/files/list") {
        if (request.method !== "GET") {
          return json({
            error: "Method not allowed"
          }, 405, request);
        }

        try {
          const publishedResult = await env.DB.prepare(`
            SELECT
              id,
              owner_username AS ownerUsername,
              original_filename AS filename,
              content_type AS contentType,
              size_bytes AS sizeBytes,
              published_at AS publishedAt
            FROM file_submissions
            WHERE status = 'published'
            ORDER BY published_at DESC, id DESC
          `).all();

          let submissions = [];

          if (publisher) {
            const result = await env.DB.prepare(`
              SELECT
                id,
                owner_username AS ownerUsername,
                original_filename AS filename,
                content_type AS contentType,
                size_bytes AS sizeBytes,
                status,
                created_at AS createdAt,
                published_at AS publishedAt
              FROM file_submissions
              ORDER BY created_at DESC, id DESC
              LIMIT 1000
            `).all();

            submissions = result.results || [];
          } else if (contributor) {
            const result = await env.DB.prepare(`
              SELECT
                id,
                owner_username AS ownerUsername,
                original_filename AS filename,
                content_type AS contentType,
                size_bytes AS sizeBytes,
                status,
                created_at AS createdAt,
                published_at AS publishedAt
              FROM file_submissions
              WHERE owner_member_id = ?
                AND status != 'published'
              ORDER BY created_at DESC, id DESC
              LIMIT 500
            `).bind(member.id).all();

            submissions = result.results || [];
          }

          return json({
            success: true,
            files: publishedResult.results || [],
            submissions
          }, 200, request);
        } catch (error) {
          console.error("File listing failed:", error);
          return json({
            error: "Could not retrieve files"
          }, 500, request);
        }
      }

      // Upload files.

      if (path === "/files/upload") {
        if (request.method !== "POST") {
          return json({
            error: "Method not allowed"
          }, 405, request);
        }

        if (!publisher && !contributor) {
          return json({
            error: "Contributor permission required"
          }, 403, request);
        }

        const length = Number(
          request.headers.get("Content-Length") || 0
        );

        if (length > MAX_UPLOAD_REQUEST) {
          return json({
            error: "Upload request is too large"
          }, 413, request);
        }

        let form;

        try {
          form = await request.formData();
        } catch {
          return json({
            error: "Expected a multipart file upload"
          }, 400, request);
        }

        const file = form.get("file");

        if (!file || typeof file.arrayBuffer !== "function") {
          return json({
            error: "Choose a file to upload"
          }, 400, request);
        }

        const filename = safeFilename(file.name);
        const type = (file.type || "").toLowerCase();

        if (!filename) {
          return json({
            error: "Invalid filename"
          }, 400, request);
        }

        if (file.size < 1 || file.size > MAX_FILE_SIZE) {
          return json({
            error: "Files must be between 1 byte and 20 MB"
          }, 413, request);
        }

        if (!ALLOWED_FILE_TYPES.has(type)) {
          return json({
            error: "This file type is not allowed"
          }, 415, request);
        }

        const key = `submissions/${member.id}/${randomHex(24)}`;

        try {
          await env.FILES.put(key, await file.arrayBuffer(), {
            httpMetadata: {
              contentType: "application/octet-stream",
              contentDisposition: "attachment"
            },
            customMetadata: {
              ownerUsername: member.username,
              originalFilename: filename
            }
          });

          let result;

          try {
            result = await env.DB.prepare(`
              INSERT INTO file_submissions
                (owner_member_id, owner_username, original_filename,
                 object_key, content_type, size_bytes, status)
              VALUES (?, ?, ?, ?, ?, ?, 'pending')
            `).bind(
              member.id,
              member.username,
              filename,
              key,
              type,
              file.size
            ).run();
          } catch (error) {
            await env.FILES.delete(key);
            throw error;
          }

          return json({
            success: true,
            submission: {
              id: result.meta.last_row_id,
              filename,
              sizeBytes: file.size,
              status: "pending"
            }
          }, 201, request);
        } catch (error) {
          console.error("Upload failed:", error);
          return json({
            error: "Could not save submission"
          }, 500, request);
        }
      }

      // View submissions.

      if (path === "/files/submissions") {
        if (request.method !== "GET") {
          return json({
            error: "Method not allowed"
          }, 405, request);
        }

        if (!publisher && !contributor) {
          return json({
            error: "Contributor permission required"
          }, 403, request);
        }

        try {
          const result = publisher
            ? await env.DB.prepare(`
                SELECT * FROM file_submissions
                WHERE status = 'pending'
                ORDER BY created_at DESC
                LIMIT 500
              `).all()
            : await env.DB.prepare(`
                SELECT * FROM file_submissions
                WHERE owner_member_id = ?
                  AND status != 'published'
                ORDER BY created_at DESC
                LIMIT 200
              `).bind(member.id).all();

          return json({
            submissions: (result.results || []).map(submissionSummary),
            publisher
          }, 200, request);
        } catch (error) {
          console.error("Submission list failed:", error);
          return json({
            error: "Could not load submissions"
          }, 500, request);
        }
      }

      // Published files are visible to all signed-in members.

      if (path === "/files/published") {
        if (request.method !== "GET") {
          return json({
            error: "Method not allowed"
          }, 405, request);
        }

        try {
          const result = await env.DB.prepare(`
            SELECT * FROM file_submissions
            WHERE status = 'published'
            ORDER BY published_at DESC
            LIMIT 1000
          `).all();

          return json({
            files: (result.results || []).map(submissionSummary)
          }, 200, request);
        } catch (error) {
          console.error("Published file list failed:", error);
          return json({
            error: "Could not load published files"
          }, 500, request);
        }
      }

      // Publish or reject pending submissions.

      const review = path.match(
        /^\/files\/submissions\/([0-9]+)\/(publish|reject)$/
      );

      if (review) {
        if (request.method !== "POST") {
          return json({
            error: "Method not allowed"
          }, 405, request);
        }

        if (!publisher) {
          return json({
            error: "Publisher permission required"
          }, 403, request);
        }

        const id = Number(review[1]);
        const action = review[2];

        try {
          const row = await env.DB.prepare(`
            SELECT * FROM file_submissions
            WHERE id = ? AND status = 'pending'
          `).bind(id).first();

          if (!row) {
            return json({
              error: "Pending submission not found"
            }, 404, request);
          }

          if (action === "publish") {
            if (!await env.FILES.head(row.object_key)) {
              return json({
                error: "The stored file is missing"
              }, 500, request);
            }

            const result = await env.DB.prepare(`
              UPDATE file_submissions
              SET status = 'published',
                  published_at = CURRENT_TIMESTAMP,
                  published_by_member_id = ?
              WHERE id = ? AND status = 'pending'
            `).bind(member.id, id).run();

            if (!result.meta.changes) {
              return json({
                error: "Submission was already reviewed"
              }, 409, request);
            }

            return json({
              success: true,
              id,
              status: "published"
            }, 200, request);
          }

          const result = await env.DB.prepare(`
            UPDATE file_submissions
            SET status = 'rejected'
            WHERE id = ? AND status = 'pending'
          `).bind(id).run();

          if (!result.meta.changes) {
            return json({
              error: "Submission was already reviewed"
            }, 409, request);
          }

          return json({
            success: true,
            id,
            status: "rejected"
          }, 200, request);
        } catch (error) {
          console.error("Submission review failed:", error);
          return json({
            error: "Could not review submission"
          }, 500, request);
        }
      }

      // Delete submissions.
      // Only administrators can delete published files.

      const deletion = path.match(
        /^\/files\/submissions\/([0-9]+)$/
      );

      if (deletion) {
        if (request.method !== "DELETE") {
          return json({
            error: "Method not allowed"
          }, 405, request);
        }

        const id = Number(deletion[1]);

        try {
          const row = await env.DB.prepare(
            "SELECT * FROM file_submissions WHERE id = ?"
          ).bind(id).first();

          if (!row) {
            return json({
              error: "Submission not found"
            }, 404, request);
          }

          const administrator = await isSiteAdministrator(
            member.id, env
          );

          if (row.status === "published" && !administrator) {
            return json({
              error: "Only a site administrator can delete published files"
            }, 403, request);
          }

          if (!administrator) {
            if (!contributor) {
              return json({
                error: "Contributor permission required"
              }, 403, request);
            }

            if (row.owner_member_id !== member.id) {
              return json({
                error: "You can delete only your own submissions"
              }, 403, request);
            }
          }

          await env.FILES.delete(row.object_key);

          await env.DB.prepare(
            "DELETE FROM file_submissions WHERE id = ?"
          ).bind(id).run();

          return json({
            success: true,
            id
          }, 200, request);
        } catch (error) {
          console.error("Submission deletion failed:", error);
          return json({
            error: "Could not delete submission"
          }, 500, request);
        }
      }

      // Download published files.

      const download = path.match(
        /^\/files\/download\/([0-9]+)$/
      );

      if (download) {
        if (request.method !== "GET") {
          return json({
            error: "Method not allowed"
          }, 405, request);
        }

        try {
          const row = await env.DB.prepare(`
            SELECT * FROM file_submissions
            WHERE id = ? AND status = 'published'
          `).bind(Number(download[1])).first();

          if (!row) {
            return json({
              error: "Published file not found"
            }, 404, request);
          }

          const object = await env.FILES.get(row.object_key);

          if (!object) {
            return json({
              error: "Stored file not found"
            }, 404, request);
          }

          const filename = row.original_filename
            .replace(/[^a-zA-Z0-9._ -]/g, "_")
            .replace(/["\\\r\n]/g, "_")
            .slice(0, 180) || "download";

          const headers = new Headers({
            "Content-Type": "application/octet-stream",
            "Content-Length": String(row.size_bytes),
            "Content-Disposition": `attachment; filename="${filename}"`,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store"
          });

          const origin = request.headers.get("Origin");

          if (origin && ALLOWED_ORIGINS.has(origin)) {
            headers.set("Access-Control-Allow-Origin", origin);
            headers.set("Access-Control-Allow-Credentials", "true");
            headers.set("Vary", "Origin");
          }

          return new Response(object.body, {
            status: 200,
            headers
          });
        } catch (error) {
          console.error("Download failed:", error);
          return json({
            error: "Could not download file"
          }, 500, request);
        }
      }

      return json({
        error: "File route not found"
      }, 404, request);
    }

    return json({
      error: "Not found"
    }, 404, request);
  }
};

