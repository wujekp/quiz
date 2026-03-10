import os
import json
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


ENCRYPTED_FILE = "questions.enc"
USERS_FILE = "users.json"
QUESTIONS_PASSWORD = "Ppawel"

MAGIC = b"QZ01"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 480000

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "zmien-to-na-wlasny-sekret")


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def decrypt_questions_file(password: str) -> str:
    if not os.path.exists(ENCRYPTED_FILE):
        raise FileNotFoundError("Brak pliku questions.enc")

    with open(ENCRYPTED_FILE, "rb") as f:
        data = f.read()

    magic = data[:len(MAGIC)]
    if magic != MAGIC:
        raise ValueError("Zły format pliku")

    offset = len(MAGIC)

    salt = data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext = data[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")


def load_questions_from_text(content: str):
    questions = []
    blocks = content.split("---")

    for block in blocks:
        q = {}

        for line in block.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue

            key, value = line.split("=", 1)
            q[key.strip()] = value.strip()

        if all(k in q for k in ["Text", "A", "B", "C", "D", "Correct"]):
            questions.append(q)

    return questions


def load_questions():
    content = decrypt_questions_file(QUESTIONS_PASSWORD)
    return load_questions_from_text(content)


def load_users():
    if not os.path.exists(USERS_FILE):
        return []

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("quiz"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        login_value = request.form.get("login", "").strip()
        password_value = request.form.get("password", "")

        users = load_users()
        user = next((u for u in users if u["login"] == login_value), None)

        if user and check_password_hash(user["password_hash"], password_value):
            session["user"] = login_value
            return redirect(url_for("quiz"))

        error = "Nieprawidłowy login lub hasło."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/quiz")
@login_required
def quiz():
    return render_template("quiz.html", username=session.get("user"))


@app.route("/api/questions")
@login_required
def api_questions():
    try:
        questions = load_questions()
        return jsonify(questions)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)