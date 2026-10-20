require("dotenv").config();
const path = require("path");
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const auth = require("./auth");

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3002;

let client = null;
let db = null;
let calllogsCol = null;
let appointmentsCol = null;
let slotcountersCol = null;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Security & CSRF check
function checkOriginHost(req) {
  const forwardedHost = req.headers["x-forwarded-host"];
  const host = forwardedHost ? forwardedHost.split(",")[0].trim() : req.headers.host;
  const origin = req.headers.origin;
  if (!origin || !host) return true;
  try {
    const originHost = new URL(origin).host;
    return originHost === host;
  } catch (e) {
    return false;
  }
}

// ----------------------------------------------------
// Public Real Estate Projects Catalog
// ----------------------------------------------------
const REAL_ESTATE_PROJECTS = [
  {
    name: "City Greens Residency",
    hindiName: "सिटी ग्रीन्स रेजिडेंसी",
    type: "Luxury Residential Flats",
    category: "Flat",
    location: "Civil Lines, Kanpur",
    priceRange: "₹45 लाख – ₹65 लाख",
    configurations: ["2 BHK Flat (1050 sq ft)", "3 BHK Flat (1450 sq ft)"],
    possession: "Ready to Move",
    amenities: ["Clubhouse", "Swimming Pool", "Gym", "24/7 Power Backup", "Covered Parking", "Kids Play Area"],
    shifts: ["10:00 AM", "2:00 PM", "5:30 PM"],
    featured: true
  },
  {
    name: "Royal Palm Villas",
    hindiName: "रॉयल पाम विला",
    type: "Premium Gated Villas",
    category: "Villa",
    location: "Ganga Barrage Road, Kanpur",
    priceRange: "₹95 लाख – ₹1.45 करोड़",
    configurations: ["3 BHK Duplex Villa (1800 sq ft)", "4 BHK Royal Villa (2500 sq ft)"],
    possession: "Ready in 6 months",
    amenities: ["Private Garden", "Gated Township", "40ft Wide Roads", "Solar Street Lights", "Community Center"],
    shifts: ["10:00 AM", "2:00 PM", "5:30 PM"],
    featured: true
  },
  {
    name: "Green Valley Plots",
    hindiName: "ग्रीन वैली प्लॉट्स",
    type: "Freehold Residential Land",
    category: "Plot",
    location: "Kalyanpur, Kanpur",
    priceRange: "₹25 लाख – ₹50 लाख",
    configurations: ["100 sq yard (900 sq ft)", "150 sq yard (1350 sq ft)", "200 sq yard (1800 sq ft)"],
    possession: "Immediate Registry (दाखिल-खारिज)",
    amenities: ["Freehold Title", "Sewer Line", "Electric Poles", "35ft Wide Roads", "Boundary Wall"],
    shifts: ["10:00 AM", "2:00 PM", "5:30 PM"],
    featured: false
  },
  {
    name: "Apex Commercial Plaza",
    hindiName: "एपेक्स कमर्शियल प्लाजा",
    type: "High-Footfall Retail & Offices",
    category: "Commercial",
    location: "MG Road, Kanpur",
    priceRange: "₹35 लाख – ₹55 लाख",
    configurations: ["Retail Shop (250 sq ft)", "Corporate Office (500 sq ft)"],
    possession: "Ready to Fit-out",
    amenities: ["Main Road Frontage", "7% Rental Yield", "Escalator", "Multi-Level Parking", "24x7 Power Backup"],
    shifts: ["10:00 AM", "2:00 PM", "5:30 PM"],
    featured: false
  }
];

// ----------------------------------------------------
// Authentication Routes
// ----------------------------------------------------
app.post("/api/login", async (req, res) => {
  if (!checkOriginHost(req)) {
    return res.status(403).json({ ok: false, error: "Cross-site request blocked." });
  }

  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: "Username and password required." });
  }

  const user = await auth.findUser(username.trim());
  if (!user) {
    return res.status(401).json({ ok: false, error: "Invalid username or password." });
  }

  const matches = await auth.verifyPassword(password, user.passwordHash);
  if (!matches) {
    return res.status(401).json({ ok: false, error: "Invalid username or password." });
  }

  const { token, user: safeUser } = auth.createSession(user);
  res.cookie("re_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
    maxAge: 24 * 60 * 60 * 1000,
    path: "/"
  });

  return res.json({ ok: true, user: safeUser });
});

app.post("/api/logout", (req, res) => {
  const cookies = auth.parseCookies(req.headers.cookie);
  const token = cookies["re_session"];
  auth.destroySession(token);
  res.clearCookie("re_session", { path: "/" });
  return res.json({ ok: true });
});

app.get("/api/me", auth.authMiddleware, (req, res) => {
  return res.json({ ok: true, user: req.user });
});

// ----------------------------------------------------
// Team Management (Admin Only)
// ----------------------------------------------------
app.get("/api/users", auth.authMiddleware, auth.requireAdmin, async (req, res) => {
  try {
    const list = await auth.listUsers();
    return res.json({ ok: true, users: list });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/users", auth.authMiddleware, auth.requireAdmin, async (req, res) => {
  try {
    const { username, password, role, name, assignedProject } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ ok: false, error: "Username and password are required." });
    }
    const created = await auth.createUser({ username, password, role, name, assignedProject });
    return res.json({ ok: true, user: created });
  } catch (err) {
    return res.status(400).json({ ok: false, error: err.message });
  }
});

app.delete("/api/users/:username", auth.authMiddleware, auth.requireAdmin, async (req, res) => {
  try {
    await auth.deleteUser(req.params.username);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(400).json({ ok: false, error: err.message });
  }
});

// ----------------------------------------------------
// Real Estate Project Catalog
// ----------------------------------------------------
app.get("/api/catalog", auth.authMiddleware, (req, res) => {
  return res.json({ ok: true, projects: REAL_ESTATE_PROJECTS });
});

// ----------------------------------------------------
// Calls & Lead Queries
// ----------------------------------------------------
app.get("/api/calls", auth.authMiddleware, async (req, res) => {
  try {
    if (!calllogsCol) return res.json({ ok: true, calls: [] });

    const { search, status, booked, limit = 100 } = req.query;
    const query = {};

    if (status && status !== "all") {
      query.status = status;
    }

    if (booked === "true") {
      query.appointmentBooked = true;
    } else if (booked === "false") {
      query.appointmentBooked = false;
    }

    if (search) {
      const regex = new RegExp(search.trim(), "i");
      query.$or = [
        { from: regex },
        { to: regex },
        { clientName: regex },
        { patientName: regex },
        { callerName: regex },
        { callSid: regex }
      ];
    }

    const calls = await calllogsCol
      .find(query)
      .sort({ startedAt: -1, createdAt: -1 })
      .limit(parseInt(limit, 10))
      .toArray();

    return res.json({ ok: true, count: calls.length, calls });
  } catch (err) {
    console.error("[calls] Error fetching calls:", err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/calls/:callSid", auth.authMiddleware, async (req, res) => {
  try {
    if (!calllogsCol) return res.status(404).json({ ok: false, error: "Database not connected" });
    const call = await calllogsCol.findOne({ callSid: req.params.callSid });
    if (!call) return res.status(404).json({ ok: false, error: "Call not found" });
    return res.json({ ok: true, call });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// Synthetic Audio WAV Generator for Browser Playback
app.get("/api/calls/:callSid/audio", auth.authMiddleware, async (req, res) => {
  try {
    const call = calllogsCol ? await calllogsCol.findOne({ callSid: req.params.callSid }) : null;
    const duration = Math.min(Math.max((call && call.durationSeconds) || 5, 2), 60);

    const sampleRate = 8000;
    const numSamples = sampleRate * duration;
    const dataSize = numSamples * 2;
    const buffer = Buffer.alloc(44 + dataSize);

    // RIFF header
    buffer.write("RIFF", 0);
    buffer.writeUInt32LE(36 + dataSize, 4);
    buffer.write("WAVE", 8);
    buffer.write("fmt ", 12);
    buffer.writeUInt32LE(16, 16);
    buffer.writeUInt16LE(1, 20); // PCM
    buffer.writeUInt16LE(1, 22); // mono
    buffer.writeUInt32LE(sampleRate, 24);
    buffer.writeUInt32LE(sampleRate * 2, 28);
    buffer.writeUInt16LE(2, 32);
    buffer.writeUInt16LE(16, 34);
    buffer.write("data", 36);
    buffer.writeUInt32LE(dataSize, 40);

    for (let i = 0; i < numSamples; i++) {
      const t = i / sampleRate;
      const freq = 420 + Math.sin(t * 3) * 40;
      const sample = Math.floor(Math.sin(2 * Math.PI * freq * t) * 6000 * Math.exp(-(t % 2) * 1.2));
      buffer.writeInt16LE(sample, 44 + i * 2);
    }

    res.setHeader("Content-Type", "audio/wav");
    res.setHeader("Content-Length", buffer.length);
    res.setHeader("Accept-Ranges", "bytes");
    return res.end(buffer);
  } catch (err) {
    return res.status(500).send("Audio streaming error");
  }
});

// ----------------------------------------------------
// Site Visits & Appointments
// ----------------------------------------------------
app.get("/api/appointments", auth.authMiddleware, async (req, res) => {
  try {
    if (!appointmentsCol) return res.json({ ok: true, appointments: [] });

    const { project, date, status } = req.query;
    const query = {};

    if (project && project !== "all") {
      query.$or = [{ projectName: project }, { doctorName: project }];
    }

    if (date) {
      query.date = date;
    }

    if (status && status !== "all") {
      query.status = status;
    }

    const appointments = await appointmentsCol
      .find(query)
      .sort({ date: 1, time: 1 })
      .toArray();

    return res.json({ ok: true, count: appointments.length, appointments });
  } catch (err) {
    console.error("[appointments] Error:", err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/appointments/:id/status", auth.authMiddleware, async (req, res) => {
  try {
    if (!appointmentsCol) return res.status(500).json({ ok: false, error: "Database not connected" });
    const { status } = req.body;
    if (!["confirmed", "pending_confirmation", "cancelled", "completed"].includes(status)) {
      return res.status(400).json({ ok: false, error: "Invalid status value" });
    }

    const result = await appointmentsCol.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status, updatedAt: new Date() } }
    );

    return res.json({ ok: true, modified: result.modifiedCount });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ----------------------------------------------------
// Analytics & Metrics
// ----------------------------------------------------
app.get("/api/analytics", auth.authMiddleware, async (req, res) => {
  try {
    const totalCalls = calllogsCol ? await calllogsCol.countDocuments() : 0;
    const totalVisits = appointmentsCol ? await appointmentsCol.countDocuments() : 0;
    const confirmedVisits = appointmentsCol ? await appointmentsCol.countDocuments({ status: "confirmed" }) : 0;
    const pendingVisits = appointmentsCol ? await appointmentsCol.countDocuments({ status: "pending_confirmation" }) : 0;

    // Conversion rate
    const conversionRate = totalCalls > 0 ? ((totalVisits / totalCalls) * 100).toFixed(1) : 0;

    // Project Breakdown
    const projectBreakdown = {};
    REAL_ESTATE_PROJECTS.forEach(p => {
      projectBreakdown[p.name] = { totalVisits: 0, category: p.category, location: p.location };
    });

    if (appointmentsCol) {
      const appts = await appointmentsCol.find({}).toArray();
      appts.forEach(a => {
        const pName = a.projectName || a.doctorName || "City Greens Residency";
        if (!projectBreakdown[pName]) {
          projectBreakdown[pName] = { totalVisits: 0, category: a.propertyType || "General", location: "Kanpur" };
        }
        projectBreakdown[pName].totalVisits += 1;
      });
    }

    // Call Durations
    let avgDuration = 0;
    if (calllogsCol) {
      const durationAgg = await calllogsCol.aggregate([
        { $group: { _id: null, avgDur: { $avg: "$durationSeconds" } } }
      ]).toArray();
      if (durationAgg.length > 0 && durationAgg[0].avgDur) {
        avgDuration = Math.round(durationAgg[0].avgDur);
      }
    }

    return res.json({
      ok: true,
      stats: {
        totalCalls,
        totalVisits,
        confirmedVisits,
        pendingVisits,
        conversionRate,
        avgDurationSeconds: avgDuration,
        projectBreakdown
      }
    });
  } catch (err) {
    console.error("[analytics] Error:", err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// Fallback to SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ----------------------------------------------------
// Start Server & Connect MongoDB
// ----------------------------------------------------
async function startServer() {
  const uri = process.env.MONGODB_URI;
  const dbName = process.env.MONGODB_DB || "realestate_portal";

  if (!uri) {
    console.error("[server] ERROR: MONGODB_URI missing in .env!");
    process.exit(1);
  }

  try {
    client = new MongoClient(uri);
    await client.connect();
    db = client.db(dbName);

    calllogsCol = db.collection("calllogs");
    appointmentsCol = db.collection("appointments");
    slotcountersCol = db.collection("slotcounters");

    console.log(`[db] Connected to MongoDB database: '${dbName}'`);
    await auth.initUsers(db);

    app.listen(PORT, () => {
      console.log(`[server] Deific Digital Real Estate Dashboard running on port ${PORT}`);
      console.log(`[server] Database: ${dbName} (isolated real estate portal records)`);
    });
  } catch (err) {
    console.error("[server] Failed to start:", err);
    process.exit(1);
  }
}

startServer();
