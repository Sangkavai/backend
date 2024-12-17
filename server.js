const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Replace with your MySQL username
  password: "Sang@9624", // Replace with your MySQL password
  database: "userDB"
});

app.post("/register", async (req, res) => {
  const { name, employeeId, email, phone, department, doj, role, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (name, employee_id, email, phone, department, doj, role, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [name, employeeId, email, phone, department, doj, role, hashedPassword],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: "Error registering user" });
      }
      res.status(201).json({ message: "User registered" });
    }
  );
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err || result.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id }, "your_jwt_secret", { expiresIn: "1h" });
    res.status(200).json({ token });
  });
});

app.get("/dashboard", (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Not authorized" });
  }

  jwt.verify(token, "your_jwt_secret", (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Token invalid" });
    }

    db.query("SELECT * FROM users WHERE id = ?", [decoded.userId], (err, result) => {
      if (err) {
        return res.status(500).json({ error: "Error fetching user details" });
      }
      res.json(result[0]);
    });
  });
});

app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
});