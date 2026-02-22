from flask import Flask, request, jsonify, send_from_directory
import sqlite3

app = Flask(__name__)
DB = "survey.db"

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            answer TEXT,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/submit", methods=["POST"])
def submit():
    data = request.json
    with sqlite3.connect(DB) as con:
        con.execute("INSERT INTO responses (name, answer) VALUES (?, ?)",
                    (data.get("name"), data.get("answer")))
    return jsonify({"status": "ok"})

@app.route("/results")
def results():
    with sqlite3.connect(DB) as con:
        rows = con.execute("SELECT name, answer, submitted_at FROM responses ORDER BY id DESC").fetchall()
    return jsonify([{"name": r[0], "answer": r[1], "time": r[2]} for r in rows])
@app.route("/resultats")
def resultats():
    return send_from_directory(".", "resultats.html")

if __name__ == "__main__":
    init_db()
    import os
app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

import json

@app.route("/admin")
def admin():
    return send_from_directory(".", "admin.html")

@app.route("/questions")
def get_questions():
    with open("questions.json", "r", encoding="utf-8") as f:
        return jsonify(json.load(f))

@app.route("/save-questions", methods=["POST"])
def save_questions():
    data = request.json
    with open("questions.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return jsonify({"status": "ok"})