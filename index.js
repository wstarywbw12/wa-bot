require("dotenv").config();
/* ================= MODULE ================= */
const { Client, LocalAuth } = require("whatsapp-web.js");
const express = require("express");
const http = require("http");
const socketIO = require("socket.io");
const qrcode = require("qrcode");
const path = require("path");
const mysql = require("mysql2/promise");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sharedSession = require("express-socket.io-session");

/* ================= APP ================= */
const app = express();
const server = http.createServer(app);
const io = socketIO(server);
const PORT = process.env.APP_PORT || 8001;

// (async () => {
//   const hash = await bcrypt.hash("admin123", 10);
//   console.log(hash);
// })();

/* ================= DB ================= */
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

/* ================= SESSION ================= */
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
});

app.use(sessionMiddleware);
io.use(sharedSession(sessionMiddleware, { autoSave: true }));

/* ================= STATE ================= */
const devices = {};

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use("/assets", express.static(path.join(__dirname, "client/assets")));

function auth(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}

/* ================= HELPER ================= */
function initDevice(id) {
  if (!devices[id]) {
    devices[id] = {
      client: null,
      state: "INIT",
      qr: null,
      info: null,
      initializing: false,
    };
  }
}

function emitStatus(id) {
  io.emit("device:status", {
    deviceId: id,
    state: devices[id].state,
  });
}

function normalize(phone) {
  phone = phone.replace(/\D/g, "");
  if (phone.startsWith("0")) phone = "62" + phone.slice(1);
  return phone;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function randomDelay(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/* ================= WA CLIENT ================= */
async function createClient(id) {
  initDevice(id);
  const d = devices[id];
  if (d.client || d.initializing) return;

  d.initializing = true;
  d.state = "INIT";
  emitStatus(id);

  d.client = new Client({
    authStrategy: new LocalAuth({
      clientId: id,
      dataPath: "./devices",
    }),
    puppeteer: {
      headless: true,
      args: ["--no-sandbox"],
    },
  });

  registerEvents(id);
  await d.client.initialize();
  d.initializing = false;
}

function registerEvents(id) {
  const d = devices[id];
  const c = d.client;

  c.on("qr", async qr => {
    d.qr = await qrcode.toDataURL(qr);
    d.state = "QR";
    emitStatus(id);
  });

  c.on("ready", () => {
    d.state = "READY";
    d.qr = null;
    d.info = {
      number: c.info?.wid?.user || "-",
      name: c.info?.pushname || "-",
    };
    emitStatus(id);
    io.emit("device:info", { deviceId: id, info: d.info });
  });

  c.on("disconnected", async () => {
    d.state = "INIT";
    emitStatus(id);
    try { await c.destroy(); } catch { }
    d.client = null;
  });
}

/* ================= LOAD DEVICE ================= */
async function loadDevices() {
  const [rows] = await db.query(
    `SELECT device_id FROM wa_devices WHERE is_active=1`
  );
  for (const r of rows) await createClient(r.device_id);
}

/* ================= AUTH ROUTE ================= */
app.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/");
  res.sendFile(path.join(__dirname, "client/login.html"));
});

app.get("/", auth, (req, res) => {
  res.sendFile(path.join(__dirname, "client/index.html"));
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM users WHERE username=? LIMIT 1",
    [username]
  );

  if (!rows.length)
    return res.json({ success: false, error: "User tidak ditemukan" });

  const valid = await bcrypt.compare(password, rows[0].password);
  if (!valid)
    return res.json({ success: false, error: "Password salah" });

  req.session.user = {
    id: rows[0].id,
    username: rows[0].username,
  };

  res.json({ success: true });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

/* ================= PROTECTED ROUTE ================= */

app.use("/api/device", auth);

/* ================= API DEVICE ================= */
app.post("/api/device", async (req, res) => {
  const { device_id, name } = req.body;
  if (!device_id)
    return res.status(400).json({ error: "device_id required" });

  await db.execute(
    `INSERT INTO wa_devices (device_id,name,is_active)
     VALUES (?,?,1)`,
    [device_id, name || device_id]
  );

  await createClient(device_id);
  io.emit("device:added", { device_id, name });

  res.json({ success: true });
});

app.delete("/api/device/:id", async (req, res) => {
  const id = req.params.id;
  const d = devices[id];

  if (d?.client) {
    try { await d.client.logout(); } catch { }
    try { await d.client.destroy(); } catch { }
  }

  delete devices[id];
  await db.execute(`DELETE FROM wa_devices WHERE device_id=?`, [id]);

  io.emit("device:removed", id);
  res.json({ success: true });
});

/* ================= API BLAST ================= */
app.post("/api/blast", async (req, res) => {
  const { device_id, message, numbers, api_key } = req.body;

  if (api_key !== process.env.BLAST_API_KEY)
    return res.status(401).json({ error: "Unauthorized" });

  const d = devices[device_id];
  if (!d || d.state !== "READY")
    return res.status(400).json({ error: "Device not ready" });

  for (const phone of numbers) {
    let status = "SENT", error = null;
    try {
      await d.client.sendMessage(
        normalize(phone) + "@c.us",
        message
      );
    } catch (e) {
      console.error(e.message);
    }
    await db.execute(
      `INSERT INTO wa_blast_logs
       (device_id,phone,message,status,error_message)
       VALUES (?,?,?,?,?)`,
      [device_id, phone, message, status, error]
    );

  }

  res.json({ success: true });
});

app.post("/api/blast/group", async (req, res) => {
  const {
    device_id,
    message,
    groups,
    delay_min = 3000,
    delay_max = 7000,
    api_key
  } = req.body;

  // 🔐 API KEY
  if (api_key !== process.env.BLAST_API_KEY)
    return res.status(401).json({ error: "Unauthorized" });

  // 🔌 DEVICE CHECK
  const d = devices[device_id];
  if (!d || d.state !== "READY")
    return res.status(400).json({ error: "Device not ready" });

  if (!Array.isArray(groups) || !groups.length)
    return res.status(400).json({ error: "Groups required" });

  let sent = 0;
  let failed = 0;
  let consecutiveFail = 0;

  for (const groupId of groups) {
    let status = "SENT";
    let error = null;

    try {
      if (!groupId.endsWith("@g.us"))
        throw new Error("Invalid group id");

      await d.client.sendMessage(groupId, message);
      sent++;
      consecutiveFail = 0;
    } catch (e) {
      status = "FAILED";
      error = e.message;
      failed++;
      consecutiveFail++;
    }

    // 🧾 LOG
    await db.execute(
      `INSERT INTO wa_blast_logs
       (device_id,phone,message,status,error_message)
       VALUES (?,?,?,?,?)`,
      [device_id, groupId, message, status, error]
    );

    // 🛑 FAIL-SAFE (ANTI BAN)
    if (consecutiveFail >= 3) {
      console.warn("🚨 STOP: too many failures");
      break;
    }

    // ⏱️ RANDOM DELAY
    const wait = randomDelay(delay_min, delay_max);
    await sleep(wait);
  }

  res.json({
    success: true,
    device_id,
    sent,
    failed,
    total: groups.length
  });
});


app.get("/api/groups/:device_id", async (req, res) => {
  const d = devices[req.params.device_id];
  if (!d || d.state !== "READY")
    return res.status(400).json({ error: "Device not ready" });

  const chats = await d.client.getChats();
  const groups = chats
    .filter(c => c.isGroup)
    .map(g => ({
      id: g.id._serialized,
      name: g.name
    }));

  res.json({ groups });
});



/* ================= SOCKET ================= */
io.on("connection", async socket => {
  if (!socket.handshake.session.user) {
    socket.disconnect();
    return;
  }

  const [rows] = await db.query(
    `SELECT device_id,name FROM wa_devices WHERE is_active=1`
  );

  socket.emit("device:list", rows);

  for (const r of rows) {
    const d = devices[r.device_id];
    if (!d) continue;
    socket.emit("device:status", {
      deviceId: r.device_id,
      state: d.state,
    });
    if (d.info)
      socket.emit("device:info", {
        deviceId: r.device_id,
        info: d.info,
      });
  }

  socket.on("device:getQr", id => {
    const d = devices[id];
    if (d?.qr)
      socket.emit("device:qr", { deviceId: id, qr: d.qr });
  });

  socket.on("device:disconnect", async id => {
    const d = devices[id];
    if (!d?.client) return;

    try { await d.client.logout(); } catch { }
    try { await d.client.destroy(); } catch { }

    d.client = null;
    d.state = "INIT";
    emitStatus(id);
    setTimeout(() => createClient(id), 3000);
  });

  socket.on("history:get", async id => {
    const [rows] = await db.query(
      `SELECT phone,message,status,created_at
       FROM wa_blast_logs
       WHERE device_id=?
       ORDER BY id DESC LIMIT 20`,
      [id]
    );
    socket.emit("history:data", { deviceId: id, rows });
  });
});

/* ================= START ================= */
server.listen(PORT, async () => {
  console.log(`🚀 http://localhost:${PORT}`);
  await loadDevices();
});
