from flask import Flask, request, jsonify, send_from_directory, session, redirect
import sqlite3, json, os, bcrypt

app = Flask(__name__)
app.secret_key = "millau2026_secret_key_change_this"
DB = "survey.db"

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS surveys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT DEFAULT 'Mon sondage',
            questions_json TEXT DEFAULT '{"sections":[]}',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_id INTEGER NOT NULL,
            answer TEXT,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (survey_id) REFERENCES surveys(id)
        )""")
        try:
            con.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        except:
            pass
        con.execute("UPDATE users SET role='admin' WHERE username='romain.monnet'")

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    return {"id": row[0], "username": row[1], "role": row[2]} if row else None

def get_survey(user_id):
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT id, title, questions_json FROM surveys WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            con.execute("INSERT INTO surveys (user_id) VALUES (?)", (user_id,))
            row = con.execute("SELECT id, title, questions_json FROM surveys WHERE user_id=?", (user_id,)).fetchone()
    return {"id": row[0], "title": row[1], "questions": json.loads(row[2])}

@app.route("/")
def home():
    return send_from_directory(".", "home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return send_from_directory(".", "register.html")
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Nom d'utilisateur et mot de passe requis"}), 400
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    try:
        with sqlite3.connect(DB) as con:
            con.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        return jsonify({"status": "ok"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ce nom d'utilisateur est deja pris"}), 400

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return send_from_directory(".", "login.html")
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT id, password_hash FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "Utilisateur introuvable"}), 401
    if not bcrypt.checkpw(password.encode("utf-8"), row[1].encode("utf-8")):
        return jsonify({"error": "Mot de passe incorrect"}), 401
    session["user_id"] = row[0]
    return jsonify({"status": "ok"})

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    return send_from_directory(".", "dashboard.html")

@app.route("/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"error": "Non connecte"}), 401
    survey = get_survey(user["id"])
    return jsonify({"user": user, "survey": survey})

@app.route("/is-admin")
def is_admin():
    user = current_user()
    if not user:
        return jsonify({"admin": False})
    return jsonify({"admin": user.get("role") == "admin"})

@app.route("/submit/<int:survey_id>", methods=["POST"])
def submit(survey_id):
    data = request.json
    with sqlite3.connect(DB) as con:
        con.execute("INSERT INTO responses (survey_id, answer) VALUES (?, ?)", (survey_id, json.dumps(data)))
    return jsonify({"status": "ok"})

@app.route("/results/<int:survey_id>")
def results(survey_id):
    with sqlite3.connect(DB) as con:
        rows = con.execute("SELECT answer, submitted_at FROM responses WHERE survey_id=? ORDER BY id DESC", (survey_id,)).fetchall()
    return jsonify([{"answer": r[0], "time": r[1]} for r in rows])

@app.route("/questions")
def get_questions():
    user = current_user()
    if not user:
        return jsonify({"error": "Non connecte"}), 401
    survey = get_survey(user["id"])
    return jsonify(survey["questions"])

@app.route("/save-questions", methods=["POST"])
def save_questions():
    user = current_user()
    if not user:
        return jsonify({"error": "Non connecte"}), 401
    data = request.json
    with sqlite3.connect(DB) as con:
        con.execute("UPDATE surveys SET questions_json=? WHERE user_id=?", (json.dumps(data), user["id"]))
    return jsonify({"status": "ok"})

@app.route("/survey/<int:survey_id>")
def survey_page(survey_id):
    return send_from_directory(".", "survey_public.html")

@app.route("/public-questions/<int:survey_id>")
def public_questions(survey_id):
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT questions_json, title FROM surveys WHERE id=?", (survey_id,)).fetchone()
    if not row:
        return jsonify({"error": "Sondage introuvable"}), 404
    return jsonify({"questions": json.loads(row[0]), "title": row[1]})

@app.route("/admin")
def admin():
    return send_from_directory(".", "admin.html")

@app.route("/resultats")
def resultats():
    return send_from_directory(".", "resultats.html")

@app.route("/resultats/<int:survey_id>")
def resultats_survey(survey_id):
    return send_from_directory(".", "resultats.html")

@app.route("/debug-users")
def debug_users():
    with sqlite3.connect(DB) as con:
        rows = con.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([{"id": r[0], "username": r[1], "role": r[2]} for r in rows])

@app.route("/admin-all-surveys")
def admin_all_surveys():
    user = current_user()
    if not user or user.get("role") != "admin":
        return jsonify({"error": "Acces refuse"}), 403
    with sqlite3.connect(DB) as con:
        rows = con.execute("""
            SELECT s.id, s.title, u.username,
            (SELECT COUNT(*) FROM responses WHERE survey_id=s.id) as response_count
            FROM surveys s JOIN users u ON s.user_id=u.id
        """).fetchall()
    return jsonify([{"id": r[0], "title": r[1], "username": r[2], "responses": r[3]} for r in rows])

@app.route("/make-me-admin")
def make_me_admin():
    with sqlite3.connect(DB) as con:
        con.execute("UPDATE users SET role='admin' WHERE username='romain.monnet'")
    return jsonify({"status": "done"})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
