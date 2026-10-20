/**
 * Authentication & RBAC Module for Real Estate Dashboard.
 * Uses native Node crypto (scrypt) with ZERO external auth packages.
 */
const crypto = require("crypto");

const SESSIONS = new Map(); // token -> { user, expiresAt }
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

let usersCollection = null;
let inMemoryUsers = [];

function scryptHash(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`${salt}:${derivedKey.toString("hex")}`);
    });
  });
}

function verifyPassword(password, storedHash) {
  return new Promise((resolve, reject) => {
    const [salt, key] = (storedHash || "").split(":");
    if (!salt || !key) return resolve(false);
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      try {
        const keyBuffer = Buffer.from(key, "hex");
        resolve(crypto.timingSafeEqual(keyBuffer, derivedKey));
      } catch (e) {
        resolve(false);
      }
    });
  });
}

async function initUsers(db) {
  usersCollection = db ? db.collection("dashboard_users") : null;
  const adminUser = process.env.DASH_USER || "admin";
  const adminPass = process.env.DASH_PASS || "Admin@RealEstate2026";
  const adminHash = await scryptHash(adminPass);

  const defaultAdmin = {
    username: adminUser,
    passwordHash: adminHash,
    role: "admin",
    name: "System Admin",
    assignedProject: "All Projects",
    createdAt: new Date().toISOString()
  };

  if (!usersCollection) {
    inMemoryUsers = [defaultAdmin];
    return;
  }

  try {
    const existingAdmin = await usersCollection.findOne({ username: adminUser });
    if (!existingAdmin) {
      await usersCollection.insertOne(defaultAdmin);
      console.log(`[auth] Created default admin '${adminUser}' in database.`);
    } else {
      await usersCollection.updateOne({ username: adminUser }, { $set: { passwordHash: adminHash } });
      console.log(`[auth] Verified admin '${adminUser}' credentials.`);
    }

    const allDbUsers = await usersCollection.find({}).toArray();
    inMemoryUsers = allDbUsers;
    console.log(`[auth] Synchronized ${inMemoryUsers.length} user(s) from realestate_portal.`);
  } catch (err) {
    console.warn("[auth] User sync warning:", err.message);
    inMemoryUsers = [defaultAdmin];
  }
}

async function findUser(username) {
  if (usersCollection) {
    try {
      const user = await usersCollection.findOne({ username });
      if (user) return user;
    } catch (e) {}
  }
  return inMemoryUsers.find(u => u.username === username);
}

async function listUsers() {
  if (usersCollection) {
    try {
      const docs = await usersCollection.find({}, { projection: { passwordHash: 0 } }).toArray();
      return docs;
    } catch (e) {}
  }
  return inMemoryUsers.map(({ passwordHash, ...rest }) => rest);
}

async function createUser({ username, password, role, name, assignedProject }) {
  const existing = await findUser(username);
  if (existing) {
    throw new Error("Username already exists");
  }

  const hash = await scryptHash(password);
  const newUser = {
    username: username.trim(),
    passwordHash: hash,
    role: role || "sales_agent",
    name: (name || username).trim(),
    assignedProject: assignedProject || "All Projects",
    createdAt: new Date().toISOString()
  };

  if (usersCollection) {
    await usersCollection.insertOne(newUser);
  }
  inMemoryUsers.push(newUser);
  const { passwordHash, ...safeUser } = newUser;
  return safeUser;
}

async function deleteUser(username) {
  if (username === (process.env.DASH_USER || "admin")) {
    throw new Error("Cannot delete primary administrator");
  }
  if (usersCollection) {
    await usersCollection.deleteOne({ username });
  }
  inMemoryUsers = inMemoryUsers.filter(u => u.username !== username);
  return true;
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const safeUser = {
    username: user.username,
    role: user.role,
    name: user.name || user.username,
    assignedProject: user.assignedProject || "All Projects"
  };
  SESSIONS.set(token, { user: safeUser, expiresAt });
  return { token, user: safeUser };
}

function getSession(token) {
  if (!token) return null;
  const session = SESSIONS.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    SESSIONS.delete(token);
    return null;
  }
  return session.user;
}

function destroySession(token) {
  if (token) SESSIONS.delete(token);
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach(pair => {
    const [name, ...rest] = pair.trim().split("=");
    if (name) cookies[name] = decodeURIComponent(rest.join("="));
  });
  return cookies;
}

function authMiddleware(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies["re_session"];
  const user = getSession(token);

  if (!user) {
    return res.status(401).json({ ok: false, error: "Unauthorized. Please sign in." });
  }

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ ok: false, error: "Forbidden. Admin access required." });
  }
  next();
}

module.exports = {
  scryptHash,
  verifyPassword,
  initUsers,
  findUser,
  listUsers,
  createUser,
  deleteUser,
  createSession,
  getSession,
  destroySession,
  parseCookies,
  authMiddleware,
  requireAdmin
};
