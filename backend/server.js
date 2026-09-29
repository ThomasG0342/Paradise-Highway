import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";

const app = express();
const db = new Database("game.db");
const SECRET = "change-moi-en-prod"; // À changer le jour de la mise en ligne

app.use(cors());
app.use(express.json());

// Initialisation des tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT);
  CREATE TABLE IF NOT EXISTS saves (user_id INTEGER PRIMARY KEY, state TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
`);

// Middleware d'authentification
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Non authentifié" });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Session invalide" });
  }
}

// Inscription
app.post("/api/register", async (req, res) => {
  const { username, password, initialState } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Champs manquants" });

  try {
    const hash = await bcrypt.hash(password, 10);
    const info = db
      .prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
      .run(username, hash);
    const userId = info.lastInsertRowid;

    if (initialState) {
      db.prepare("INSERT INTO saves (user_id, state) VALUES (?, ?)").run(
        userId,
        JSON.stringify(initialState)
      );
    }

    const token = jwt.sign({ id: userId, username }, SECRET, { expiresIn: "30d" });
    res.json({ token, username });
  } catch (e) {
    res.status(400).json({ error: "Ce pseudo est déjà pris" });
  }
});

// Connexion
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Identifiants incorrects" });
  }

  const save = db.prepare("SELECT state FROM saves WHERE user_id = ?").get(user.id);
  const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: "30d" });

  res.json({ token, username: user.username, state: save ? JSON.parse(save.state) : null });
});

// Reconnexion automatique (vérifie le token et renvoie la sauvegarde)
app.get("/api/me", auth, (req, res) => {
  const save = db.prepare("SELECT state FROM saves WHERE user_id = ?").get(req.user.id);
  res.json({ username: req.user.username, state: save ? JSON.parse(save.state) : null });
});

// Sauvegarde
app.put("/api/save", auth, (req, res) => {
  db.prepare(
    `
    INSERT INTO saves (user_id, state, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET state = excluded.state, updated_at = CURRENT_TIMESTAMP
  `
  ).run(req.user.id, JSON.stringify(req.body));
  res.json({ ok: true });
});

app.listen(3000, () => console.log("Serveur démarré sur http://localhost:3000"));
