require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = 3000;

// Intencionalmente fraco para o lab
const SECRET = process.env.JWT_SECRET || "supersecret";

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      password TEXT,
      role TEXT,
      flag TEXT
    )
  `);

  db.run(`
    INSERT INTO users (username, password, role, flag)
    VALUES ('admin', 'admin123', 'admin', 'FLAG{idor_admin_profile}')
  `);

  db.run(`
    INSERT INTO users (username, password, role, flag)
    VALUES ('alice', '123456', 'user', 'FLAG{user_enum_success}')
  `);

  db.run(`
    INSERT INTO users (username, password, role, flag)
    VALUES ('bob', 'password', 'user', NULL)
  `);
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Token ausente" });
  }

  const token = authHeader.replace("Bearer ", "");

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Token inválido" });
  }
}

app.get("/", (req, res) => {
  res.json({
    message: "CTF Web Lab API",
    hint: "Nem tudo está documentado."
  });
});

// DESAFIO 1 — Reconhecimento
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send(`
User-agent: *
Disallow: /hidden
`);
});

app.get("/hidden", (req, res) => {
  res.json({
    challenge: "Recon",
    flag: "FLAG{recon_inicial}"
  });
});

// DESAFIO 2 — Enumeração de usuários
app.get("/users", (req, res) => {
  db.all(`SELECT id, username, role, flag FROM users`, (err, users) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    res.json(users);
  });
});

// DESAFIO 3 — IDOR
app.get("/users/:id", (req, res) => {
  const id = req.params.id;

  // Intencionalmente vulnerável
  const query = `SELECT id, username, role, flag FROM users WHERE id = ${id}`;

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (!user) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    res.json(user);
  });
});

// DESAFIO 4 — SQL Injection no login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Intencionalmente vulnerável
  const query = `
    SELECT id, username, role
    FROM users
    WHERE username = '${username}'
    AND password = '${password}'
  `;

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        query
      });
    }

    if (!user) {
      return res.status(401).json({
        message: "Credenciais inválidas"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role
      },
      SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login realizado",
      token,
      flag: user.role === "admin" ? "FLAG{sqli_login_bypass}" : undefined
    });
  });
});

// DESAFIO 5 — JWT fraco
app.get("/admin", authMiddleware, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Acesso negado. Apenas administradores."
    });
  }

  res.json({
    message: "Área administrativa",
    flag: "FLAG{jwt_admin_access}"
  });
});

app.listen(PORT, () => {
  console.log(`API rodando em http://localhost:${PORT}`);
});