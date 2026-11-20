const express = require("express");
const multer = require("multer");
const { PDFParse } = require("pdf-parse");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const fs = require("fs");

console.log("LOKASI SERVER:", __dirname);

for (const file of ["index.html", "beranda.html", "tentang.html", "register.html" ,"login.html" ]) {
  console.log(
    file,
    fs.existsSync(path.join(__dirname, file))
  );
}

// MENYAJIKAN FILE HTML, CSS, DAN JS
app.use(express.static(path.join(__dirname,"public")));

// =================================
// 1. DATABASE
// =================================

const db = new Database("ringkas-yuk.db");

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expires INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    request_type TEXT NOT NULL,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    estimated_cost_usd REAL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_usage_user
  ON usage_logs(user_id);
`);

// MIGRASI DATABASE LAMA

const kolomUsers = db.prepare(
  "PRAGMA table_info(users)"
).all().map(kolom => kolom.name);

const kolomKuota = [
  ["last_request_at", "INTEGER"],
  ["text_used", "INTEGER NOT NULL DEFAULT 0"],
  ["pdf_used", "INTEGER NOT NULL DEFAULT 0"],
  ["photo_used", "INTEGER NOT NULL DEFAULT 0"],
  ["quota_reset_date", "TEXT"]
];

for (const [nama, tipe] of kolomKuota) {
  if (!kolomUsers.includes(nama)) {
    db.exec(`
      ALTER TABLE users
      ADD COLUMN ${nama} ${tipe}
    `);
  }
}

// =================================
// 2. KONFIGURASI SESSION
// =================================

class SQLiteSessionStore extends session.Store {

  get(sid, callback) {
    try {
      const row = db.prepare(
        "SELECT sess, expires FROM sessions WHERE sid = ?"
      ).get(sid);

      if (!row || row.expires <= Date.now()) {
        if (row) this.destroy(sid, () => {});
        return callback(null, null);
      }

      callback(null, JSON.parse(row.sess));

    } catch (error) {
      callback(error);
    }
  }

  set(sid, sess, callback = () => {}) {
    try {
      const expires = sess.cookie?.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + 7 * 24 * 60 * 60 * 1000;

      db.prepare(`
        INSERT OR REPLACE INTO sessions
        (sid, sess, expires)
        VALUES (?, ?, ?)
      `).run(sid, JSON.stringify(sess), expires);

      callback(null);

    } catch (error) {
      callback(error);
    }
  }

  destroy(sid, callback = () => {}) {
    try {
      db.prepare(
        "DELETE FROM sessions WHERE sid = ?"
      ).run(sid);

      callback(null);

    } catch (error) {
      callback(error);
    }
  }

  touch(sid, sess, callback = () => {}) {
    this.set(sid, sess, callback);
  }
}

// HAPUS SESSION KEDALUWARSA

db.prepare(
  "DELETE FROM sessions WHERE expires <= ?"
).run(Date.now());

// =================================
// 3. MIDDLEWARE
// =================================

app.set("trust proxy", 1);

app.use(express.json({
  limit: "1mb"
}));

if (process.env.NODE_ENV === "production" &&
    !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET wajib diatur di environment.");
}

app.use(session({
  store: new SQLiteSessionStore(),

  secret: process.env.SESSION_SECRET ||
    crypto.randomBytes(32).toString("hex"),

  resave: false,
  saveUninitialized: false,
  rolling: true,

  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// FRONTEND HANYA DARI FOLDER PUBLIC

app.use(express.static(
  path.join(__dirname, "public")
));

// =================================
// 4. KONFIGURASI UPLOAD
// =================================

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024
  },
  fileFilter: (req, file, callback) => {
    const tipeDiizinkan = [
      "application/pdf",
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (!tipeDiizinkan.includes(file.mimetype)) {
      return callback(
        new Error("Gunakan PDF, JPG, PNG, atau WEBP.")
      );
    }

    callback(null, true);
  }
});

// =================================
// 4. PEMERIKSAAN LOGIN
// =================================

function getTodayWITA() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Makassar",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(new Date());
}

function checkQuota(user, requestType) {
  const today = getTodayWITA();

  const isNewDay = user.quota_reset_date !== today;

  const textUsed = isNewDay ? 0 : user.text_used;
  const pdfUsed = isNewDay ? 0 : user.pdf_used;
  const photoUsed = isNewDay ? 0 : user.photo_used;

  const limits = {
    text: 3,
    pdf: 1,
    photo: 1
  };

  const usage = {
    text: textUsed,
    pdf: pdfUsed,
    photo: photoUsed
  };

  if (usage[requestType] >= limits[requestType]) {
    return {
      allowed: false,
      error: `Batas ringkasan ${requestType} harian sudah tercapai.`
    };
  }

  if (
    user.last_request_at &&
    Date.now() - user.last_request_at < 30000
  ) {
    const remaining = Math.ceil(
      (30000 - (Date.now() - user.last_request_at)) / 1000
    );

    return {
      allowed: false,
      error: `Tunggu ${remaining} detik sebelum meringkas lagi.`
    };
  }

  return {
    allowed: true,
    today,
    usage,
    limits
  };
}

function requireAuth(req, res, next) {

  if (!req.session.userId) {
    return res.status(401).json({
      error: "Silakan login terlebih dahulu."
    });
  }

  next();
}

// Fitur route login, registrasi,
// ringkas, kuota, dan upload
// akan ditambahkan pada tahap berikutnya.

// =================================
// 5. REGISTER
// =================================

app.post("/api/register", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Email dan password wajib diisi."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        error: "Format email tidak valid."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password minimal 8 karakter."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (email, password_hash)
      VALUES (?, ?)
    `).run(email, passwordHash);

    req.session.regenerate((error) => {
      if (error) {
        return res.status(500).json({
          error: "Gagal membuat sesi akun."
        });
      }

      req.session.userId = Number(result.lastInsertRowid);
      req.session.email = email;

      req.session.save((saveError) => {
        if (saveError) {
          return res.status(500).json({
            error: "Akun dibuat, tetapi sesi login gagal."
          });
        }

        res.json({
          message: "Pendaftaran berhasil!",
          user: { email }
        });
      });
    });

  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "Email sudah terdaftar."
      });
    }

    console.error("Register error:", error);

    res.status(500).json({
      error: "Pendaftaran gagal."
    });
  }
});


// =================================
// 6. LOGIN
// =================================

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const user = db.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).get(email);

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Email atau password salah."
      });
    }

    req.session.regenerate((error) => {
      if (error) {
        return res.status(500).json({
          error: "Gagal membuat sesi login."
        });
      }

      req.session.userId = user.id;
      req.session.email = user.email;

      req.session.save((saveError) => {
        if (saveError) {
          return res.status(500).json({
            error: "Gagal menyimpan sesi login."
          });
        }

        res.json({
          message: "Login berhasil!",
          user: { email: user.email }
        });
      });
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Login gagal."
    });
  }
});


// =================================
// 7. CEK STATUS LOGIN
// =================================

app.get("/api/me", (req, res) => {

  if (!req.session.userId) {
    return res.json({
      authenticated: false
    });
  }

  res.json({
    authenticated: true,
    user: {
      email: req.session.email
    }
  });
});


// =================================
// 8. LOGOUT
// =================================

app.post("/api/logout", (req, res) => {

  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: "Gagal logout."
      });
    }

    res.clearCookie("connect.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    });

    res.json({
      message: "Berhasil logout."
    });
  });
});
// =================================
// 9. RINGKAS TEKS, PDF, DAN FOTO
// =================================

app.post(
  "/api/ringkas",
  requireAuth,
  upload.single("file"),
  async (req, res) => {

    let parser;

    console.log("RINGKAS YUK: ROUTE VERSI BARU TERPANGGIL");
    
    try {
      const { materi, panjang, bentuk } = req.body || {};

      if (!process.env.OPENAI_API_KEY) {
        return res.status(500).json({
          error: "API key belum diatur dalam file .env."
        });
      }

      // MENENTUKAN JENIS RINGKASAN

      let requestType = "text";
      let teksMateri = typeof materi === "string"
        ? materi.trim()
        : "";

      let gambar = null;

      if (req.file) {

        if (req.file.mimetype === "application/pdf") {

          requestType = "pdf";

          parser = new PDFParse({
            data: req.file.buffer
          });

          const hasilPDF = await parser.getText();

          teksMateri = hasilPDF.text.trim();

          if (!teksMateri) {
            return res.status(400).json({
              error: "PDF tidak memiliki teks yang bisa dibaca. PDF hasil scan memerlukan OCR."
            });
          }

        } else {

          requestType = "photo";

          gambar = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
        }
      }

      if (!teksMateri && !gambar) {
        return res.status(400).json({
          error: "Masukkan materi atau pilih file terlebih dahulu."
        });
      }

      // BATAS JUMLAH KATA

      if (
        requestType === "text" &&
        teksMateri.split(/\s+/).filter(Boolean).length > 1500
      ) {
        return res.status(400).json({
          error: "Maksimal 1.500 kata untuk ringkasan teks."
        });
      }

      if (teksMateri.length > 30000) {
        return res.status(400).json({
          error: "Materi terlalu panjang. Coba bagi menjadi beberapa bagian."
        });
      }

      // AMBIL DATA PENGGUNA

      const user = db.prepare(
        "SELECT * FROM users WHERE id = ?"
      ).get(req.session.userId);

      if (!user) {
        return res.status(401).json({
          error: "Akun tidak ditemukan. Silakan login kembali."
        });
      }

      // PEMERIKSAAN KUOTA

      const quota = checkQuota(user, requestType);

      if (!quota.allowed) {
        return res.status(429).json({
          error: quota.error
        });
      }

      // INSTRUKSI RINGKASAN

      const instruksiPanjang = {
        short: "Buat ringkasan sangat singkat, hanya inti materi.",
        medium: "Buat ringkasan sedang yang mencakup gagasan utama dan fakta penting.",
        long: "Buat ringkasan lengkap dengan penjelasan konsep dan fakta penting."
      };

      const instruksiBentuk = {
        paragraph: "Sajikan hasil dalam paragraf yang runtut.",
        points: "Sajikan hasil sebagai poin-poin terstruktur."
      };

      const instruksi = [
        "Kamu adalah asisten belajar Ringkas Yuk!.",
        "Ringkas materi dalam bahasa Indonesia yang mudah dipahami.",
        "Pertahankan gagasan utama, fakta, dan istilah penting.",
        "Jangan menambahkan fakta yang tidak terdapat dalam materi.",
        instruksiPanjang[panjang] || instruksiPanjang.medium,
        instruksiBentuk[bentuk] || instruksiBentuk.paragraph
      ].join(" ");

      // INPUT AI

      const isiInput = gambar
        ? [{
            role: "user",
            content: [
              {
                type: "input_text",
                text: instruksi
              },
              {
                type: "input_image",
                image_url: gambar
              }
            ]
          }]
        : `${instruksi}\n\nMateri:\n${teksMateri}`;

      // HUBUNGKAN KE OPENAI

      const response = await fetch(
        "https://api.openai.com/v1/responses",
        {
          method: "POST",
          signal: AbortSignal.timeout(60000),
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`
          },
          body: JSON.stringify({
            model: "gpt-4.1-mini",
            input: isiInput
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        console.error("Kesalahan API:", data);

        return res.status(502).json({
          error: "Permintaan AI gagal. Periksa API key, saldo, dan akses model."
        });
      }

      const ringkasan = (data.output || [])
        .flatMap(item => item.content || [])
        .filter(item => item.type === "output_text")
        .map(item => item.text)
        .join("\n");

      if (!ringkasan) {
        return res.status(502).json({
          error: "AI tidak mengembalikan teks ringkasan."
        });
      }

      // SIMPAN KUOTA SETELAH BERHASIL

      const kolomKuota = {
        text: "text_used",
        pdf: "pdf_used",
        photo: "photo_used"
      };

      const kolom = kolomKuota[requestType];

      const jumlahSebelumnya =
        quota.usage[requestType];

      db.prepare(`
        UPDATE users
        SET ${kolom} = ?,
            quota_reset_date = ?,
            last_request_at = ?
        WHERE id = ?
      `).run(
        jumlahSebelumnya + 1,
        quota.today,
        Date.now(),
        req.session.userId
      );

      // CATAT PENGGUNAAN TOKEN

      const inputTokens = data.usage?.input_tokens || 0;
      const outputTokens = data.usage?.output_tokens || 0;
      const totalTokens = data.usage?.total_tokens ||
        inputTokens + outputTokens;

      const estimatedCost =
        (inputTokens * 0.40 + outputTokens * 1.60) / 1000000;

      db.prepare(`
        INSERT INTO usage_logs (
          user_id,
          request_type,
          input_tokens,
          output_tokens,
          total_tokens,
          estimated_cost_usd
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        req.session.userId,
        requestType,
        inputTokens,
        outputTokens,
        totalTokens,
        estimatedCost
      );

      res.json({
        ringkasan,
        usage: {
          type: requestType,
          used: jumlahSebelumnya + 1,
          remaining: quota.limits[requestType] - jumlahSebelumnya - 1
        }
      });

    } catch (error) {

      console.error("Kesalahan server:", error);

      res.status(500).json({
        error: error.code === "LIMIT_FILE_SIZE"
          ? "Ukuran file maksimal 10 MB."
          : "Server gagal memproses: " + error.message
      });

    } finally {

      if (parser) {
        await parser.destroy().catch(() => {});
      }

    }
  }
); 
// =================================
// 10. PENANGANAN ERROR UPLOAD
// =================================

app.use((error, req, res, next) => {
  console.error("Error:", error);

  if (error.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({
      error: "Ukuran file maksimal 10 MB."
    });
  }

  if (error.message === "Gunakan PDF, JPG, PNG, atau WEBP.") {
    return res.status(400).json({
      error: error.message
    });
  }

  res.status(500).json({
    error: "Terjadi kesalahan pada server."
  });
});
// =================================
// 11. JALANKAN SERVER
// =================================
// =================================
// ROUTING HALAMAN WEBSITE
// =================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/beranda.html", (req, res) => {
  res.sendFile(path.join(__dirname, "beranda.html"));
});

app.get("/tentang.html", (req, res) => {
  res.sendFile(path.join(__dirname, "tentang.html"));
});

app.get("/register.html", (req, res) => {
  res.sendFile(path.join(__dirname, "register.html"));
});

app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});


app.listen(PORT, () => {
  console.log("Ringkas Yuk! berhasil dijalankan.");
  console.log(`Link website: http://localhost:${PORT}`);
});