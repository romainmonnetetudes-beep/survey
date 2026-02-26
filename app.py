from flask import Flask, request, jsonify, send_from_directory, session, redirect
import json, os, bcrypt
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = "millau2026_secret_key_change_this"

def get_db():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise Exception("DATABASE_URL not set - check Railway environment variables")
    conn = psycopg2.connect(db_url)
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS surveys (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            title TEXT DEFAULT 'Mon sondage',
            questions_json TEXT DEFAULT '{"sections":[]}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS responses (
            id SERIAL PRIMARY KEY,
            survey_id INTEGER NOT NULL REFERENCES surveys(id),
            answer TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Login logs table — records every successful login
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            username TEXT,
            ip_address TEXT,
            logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cur.close()
    conn.close()

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, username, role FROM users WHERE id=%s", (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return dict(row) if row else None

def get_survey(user_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, title, questions_json FROM surveys WHERE user_id=%s", (user_id,))
    row = cur.fetchone()
    if not row:
        cur.execute("INSERT INTO surveys (user_id) VALUES (%s) RETURNING id, title, questions_json", (user_id,))
        row = cur.fetchone()
        conn.commit()
    cur.close()
    conn.close()
    return {"id": row["id"], "title": row["title"], "questions": json.loads(row["questions_json"])}

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
    role = "admin" if username == "romain.monnet" else "user"
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", (username, password_hash, role))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "ok"})
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Ce nom d'utilisateur est deja pris"}), 400

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return send_from_directory(".", "login.html")
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({"error": "Utilisateur introuvable"}), 401
    if not bcrypt.checkpw(password.encode("utf-8"), row[1].encode("utf-8")):
        return jsonify({"error": "Mot de passe incorrect"}), 401

    # Save user in session
    session["user_id"] = row[0]

    # Log this login — never crash if logging fails
    try:
        conn2 = get_db()
        cur2 = conn2.cursor()
        cur2.execute(
            "INSERT INTO login_logs (user_id, username, ip_address) VALUES (%s, %s, %s)",
            (row[0], username, request.remote_addr)
        )
        conn2.commit()
        cur2.close()
        conn2.close()
    except:
        pass

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
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO responses (survey_id, answer) VALUES (%s, %s)", (survey_id, json.dumps(data)))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/results/<int:survey_id>")
def results(survey_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT answer, submitted_at FROM responses WHERE survey_id=%s ORDER BY id DESC", (survey_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{"answer": r[0], "time": str(r[1])} for r in rows])

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
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE surveys SET questions_json=%s WHERE user_id=%s", (json.dumps(data), user["id"]))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/survey/<int:survey_id>")
def survey_page(survey_id):
    return send_from_directory(".", "survey_public.html")

@app.route("/public-questions/<int:survey_id>")
def public_questions(survey_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT questions_json, title FROM surveys WHERE id=%s", (survey_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({"error": "Sondage introuvable"}), 404
    return jsonify({"questions": json.loads(row[0]), "title": row[1]})

@app.route("/surveys")
def surveys_page():
    return send_from_directory(".", "surveys.html")

@app.route("/all-surveys")
def all_surveys():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT s.id, s.title, u.username,
        (SELECT COUNT(*) FROM responses WHERE survey_id=s.id) as response_count
        FROM surveys s JOIN users u ON s.user_id=u.id
        ORDER BY s.created_at ASC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{"id": r[0], "title": r[1], "username": r[2], "responses": r[3]} for r in rows])

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
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "role": r[2]} for r in rows])

@app.route("/admin-users")
def admin_users():
    user = current_user()
    if not user or user.get("role") != "admin":
        return jsonify({"error": "Acces refuse"}), 403
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.username, u.role, u.created_at,
        (SELECT COUNT(*) FROM responses r
         JOIN surveys s ON r.survey_id = s.id
         WHERE s.user_id = u.id) as response_count,
        (SELECT id FROM surveys WHERE user_id = u.id LIMIT 1) as survey_id
        FROM users u ORDER BY u.created_at ASC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{
        "id": r[0], "username": r[1], "role": r[2],
        "created_at": str(r[3]), "responses": r[4], "survey_id": r[5]
    } for r in rows])

@app.route("/admin-reset-password", methods=["POST"])
def admin_reset_password():
    user = current_user()
    if not user or user.get("role") != "admin":
        return jsonify({"error": "Acces refuse"}), 403
    data = request.json
    target_id = data.get("user_id")
    new_password = data.get("new_password")
    if not new_password or len(new_password) < 6:
        return jsonify({"error": "Mot de passe trop court"}), 400
    password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (password_hash, target_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/admin-all-surveys")
def admin_all_surveys():
    user = current_user()
    if not user or user.get("role") != "admin":
        return jsonify({"error": "Acces refuse"}), 403
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT s.id, s.title, u.username,
        (SELECT COUNT(*) FROM responses WHERE survey_id=s.id) as response_count
        FROM surveys s JOIN users u ON s.user_id=u.id
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{"id": r[0], "title": r[1], "username": r[2], "responses": r[3]} for r in rows])

@app.route("/admin-login-logs")
def admin_login_logs():
    user = current_user()
    if not user or user.get("role") != "admin":
        return jsonify({"error": "Acces refuse"}), 403
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT username, ip_address, logged_at
        FROM login_logs
        ORDER BY logged_at DESC
        LIMIT 50
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{
        "username": r[0],
        "ip": r[1],
        "time": str(r[2])
    } for r in rows])

@app.route("/admin-dashboard")
def admin_dashboard():
    user = current_user()
    if not user or user.get("role") != "admin":
        return redirect("/login")
    return send_from_directory(".", "admin_dashboard.html")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
