const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const db = new sqlite3.Database("./database.db");

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "sbs-secret",
    resave: false,
    saveUninitialized: false
}));

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            author TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    const adminPassword = bcrypt.hashSync("admin123", 10);

    db.run(`
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    `, ["admin", adminPassword, "admin"]);
});

function requireReporter(req, res, next) {
    if (!req.session.user) return res.redirect("/login");

    if (
        req.session.user.role === "reporter" ||
        req.session.user.role === "admin"
    ) {
        next();
    } else {
        res.send("권한 없음");
    }
}

function requireAdmin(req, res, next) {
    if (!req.session.user) return res.redirect("/login");

    if (req.session.user.role === "admin") {
        next();
    } else {
        res.send("운영자만 접근 가능");
    }
}

app.get("/", (req, res) => {
    db.all("SELECT * FROM news ORDER BY id DESC", (err, rows) => {
        res.render("index", {
            news: rows,
            user: req.session.user
        });
    });
});

app.get("/news/:id", (req, res) => {
    db.get(
        "SELECT * FROM news WHERE id = ?",
        [req.params.id],
        (err, row) => {
            if (!row) return res.send("뉴스 없음");

            res.render("news", {
                article: row,
                user: req.session.user
            });
        }
    );
});

app.get("/login", (req, res) => {
    res.render("login", {
        error: null
    });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (!user) {
                return res.render("login", {
                    error: "아이디가 존재하지 않습니다."
                });
            }

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.render("login", {
                    error: "비밀번호가 틀렸습니다."
                });
            }

            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role
            };

            res.redirect("/");
        }
    );
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

app.get("/write", requireReporter, (req, res) => {
    res.render("write", {
        user: req.session.user
    });
});

app.post("/write", requireReporter, (req, res) => {
    const { title, content } = req.body;

    db.run(
        "INSERT INTO news (title, content, author) VALUES (?, ?, ?)",
        [title, content, req.session.user.username],
        () => {
            res.redirect("/");
        }
    );
});

app.get("/admin", requireAdmin, (req, res) => {
    res.render("admin", {
        user: req.session.user
    });
});

app.post("/admin/create-reporter", requireAdmin, async (req, res) => {
    const { username, password } = req.body;

    const hashed = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [username, hashed, "reporter"],
        (err) => {
            if (err) {
                return res.send("이미 존재하는 계정");
            }

            res.redirect("/admin");
        }
    );
});



app.get("/edit/:id", requireReporter, (req, res) => {
    db.get("SELECT * FROM news WHERE id = ?", [req.params.id], (err, article) => {
        if (!article) return res.send("기사 없음");

        res.render("edit", {
            article,
            user: req.session.user
        });
    });
});

app.post("/edit/:id", requireReporter, (req, res) => {
    const { title, content } = req.body;

    db.run(
        "UPDATE news SET title = ?, content = ? WHERE id = ?",
        [title, content, req.params.id],
        () => {
            res.redirect("/news/" + req.params.id);
        }
    );
});

app.post("/delete/:id", requireReporter, (req, res) => {
    db.run(
        "DELETE FROM news WHERE id = ?",
        [req.params.id],
        () => {
            res.redirect("/");
        }
    );
});

app.listen(3000, () => {
    console.log("SBS 서버 실행 중");
});