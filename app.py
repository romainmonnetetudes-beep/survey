from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
import sqlite3, json, os, bcrypt

app = Flask(__name__)

# Secret key for sessions — this encrypts the session cookie
# Sessions let Flask remember who is logged in between requests
app.secret_key = "@3Co3#zMLCne!onq$f?bo3PQp"

DB = "survey.db"

# ============================================
# DATABASE SETUP
# Creates all tables if they don't exist yet
# ============================================
def init_db():
    with sqlite3.connect(DB) as con:

        # USERS table — stores login info
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # SURVEYS table — each user can have one survey
        con.execute("""
            CREATE TABLE IF NOT EXISTS surveys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT DEFAULT 'Mon sondage',
                questions_json TEXT DEFAULT '{"sections":[]}',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # RESPONSES table — answers submitted to a survey
        con.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                survey_id INTEGER NOT NULL,
                answer TEXT,
                submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (survey_id) REFERENCES surveys(id)
            )

        # Give romain.monnet the admin role if not already set
with sqlite3.connect(DB) as con:
    # Add role column if it doesn't exist yet
    try:
        con.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except:
        pass  # Column already exists, no problem

    # Make romain.monnet an admin
    con.execute("UPDATE users SET role='admin' WHERE username='romain.monnet'")
        """)

# ============================================
# HELPER — get current logged in user from session
# Returns user dict or None if not logged in
# ============================================
def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    return {"id": row[0], "username": row[1], "role": row[2]} if row else None

# ============================================
# HELPER — get or create survey for a user
# ============================================
def get_survey(user_id):
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT id, title, questions_json FROM surveys WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            # Create a default survey for new users
            con.execute("INSERT INTO surveys (user_id) VALUES (?)", (user_id,))
            row = con.execute("SELECT id, title, questions_json FROM surveys WHERE user_id=?", (user_id,)).fetchone()
    return {"id": row[0], "title": row[1], "questions": json.loads(row[2])}

# ============================================
# HOME PAGE
# ============================================
@app.route("/")
def home():
    return send_from_directory(".", "home.html")

# ============================================
# REGISTER — create a new account
# ============================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return send_from_directory(".", "register.html")

    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Nom d'utilisateur et mot de passe requis"}), 400

    # Hash the password — NEVER store plain text passwords!
    # bcrypt.hashpw scrambles it so even you can't read it
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        with sqlite3.connect(DB) as con:
            con.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        return jsonify({"status": "ok"})
    except sqlite3.IntegrityError:
        # UNIQUE constraint failed = username already taken
        return jsonify({"error": "Ce nom d'utilisateur est déjà pris"}), 400

# ============================================
# LOGIN — check credentials and start session
# ============================================
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

    # bcrypt.checkpw compares the entered password with the stored hash
    if not bcrypt.checkpw(password.encode("utf-8"), row[1].encode("utf-8")):
        return jsonify({"error": "Mot de passe incorrect"}), 401

    # Save user ID in session — this is how Flask remembers who's logged in
    session["user_id"] = row[0]
    return jsonify({"status": "ok"})

# ============================================
# LOGOUT — clear the session
# ============================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ============================================
# DASHBOARD — user's personal page after login
# ============================================
@app.route("/dashboard")
def dashboard():
    return send_from_directory(".", "dashboard.html")

# ============================================
# GET CURRENT USER INFO — called by frontend JS
# ============================================
@app.route("/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"error": "Non connecte"}), 401
    survey = get_survey(user["id"])
    return jsonify({"user": user, "survey": survey})

# ============================================
# SUBMIT A SURVEY RESPONSE
# ============================================
@app.route("/submit/<int:survey_id>", methods=["POST"])
def submit(survey_id):
    data = request.json
    with sqlite3.connect(DB) as con:
        con.execute("INSERT INTO responses (survey_id, answer) VALUES (?, ?)",
                    (survey_id, json.dumps(data)))
    return jsonify({"status": "ok"})

# ============================================
# GET RESULTS FOR A SURVEY
# ============================================
@app.route("/results/<int:survey_id>")
def results(survey_id):
    with sqlite3.connect(DB) as con:
        rows = con.execute(
            "SELECT answer, submitted_at FROM responses WHERE survey_id=? ORDER BY id DESC",
            (survey_id,)
        ).fetchall()
    return jsonify([{"answer": r[0], "time": r[1]} for r in rows])

# ============================================
# GET QUESTIONS FOR USER'S SURVEY
# ============================================
@app.route("/questions")
def get_questions():
    user = current_user()
    if not user:
        return jsonify({"error": "Non connecte"}), 401
    survey = get_survey(user["id"])
    return jsonify(survey["questions"])

# ============================================
# SAVE QUESTIONS FOR USER'S SURVEY
# ============================================
@app.route("/save-questions", methods=["POST"])
def save_questions():
    user = current_user()
    if not user:
        return jsonify({"error": "Non connecte"}), 401
    data = request.json
    with sqlite3.connect(DB) as con:
        con.execute("UPDATE surveys SET questions_json=? WHERE user_id=?",
                    (json.dumps(data), user["id"]))
    return jsonify({"status": "ok"})

# ============================================
# PUBLIC SURVEY PAGE — anyone can fill this in
# Accessed via /survey/<survey_id>
# ============================================
@app.route("/survey/<int:survey_id>")
def survey_page(survey_id):
    return send_from_directory(".", "survey_public.html")

# ============================================
# GET PUBLIC QUESTIONS for a survey by ID
# ============================================
@app.route("/public-questions/<int:survey_id>")
def public_questions(survey_id):
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT questions_json, title FROM surveys WHERE id=?", (survey_id,)).fetchone()
    if not row:
        return jsonify({"error": "Sondage introuvable"}), 404
    return jsonify({"questions": json.loads(row[0]), "title": row[1]})

# ============================================
# ADMIN — keep existing admin for now
# ============================================
@app.route("/admin")
def admin():
    return send_from_directory(".", "admin.html")

@app.route("/is-admin")
def is_admin():
    user = current_user()
    if not user:
        return jsonify({"admin": False})
    return jsonify({"admin": user.get("role") == "admin"})

# ============================================
# STATIC PAGES
# ============================================
@app.route("/resultats")
def resultats():
    return send_from_directory(".", "resultats.html")


    @app.route("/debug-users")
def debug_users():
    with sqlite3.connect(DB) as con:
        rows = con.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([{"id": r[0], "username": r[1], "role": r[2]} for r in rows])

# ============================================
# START THE APP
# ============================================
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
