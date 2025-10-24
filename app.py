
from flask import Flask, request, jsonify, render_template, send_from_directory, make_response, redirect, url_for, session
from subprocess import Popen, PIPE
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os
import json
import random
import time
import threading
import sys
import stat
import re
import uuid


import sqlite3
import bcrypt

from functools import wraps
from flask import redirect, url_for, session

sys.stdout.reconfigure(line_buffering=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "pseudo" not in session:
            return redirect(url_for("connexion"))
        return f(*args, **kwargs)
    return decorated_function

# --- Auth config ---
if 'app' not in globals():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

socketio = SocketIO(app)

# --- Mail configuration (Gmail) ---
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "c4bot.noreply@gmail.com"          # ton adresse Gmail
app.config["MAIL_PASSWORD"] = "ayxc knet gmcs bobn"                    # ton mot de passe d'application Gmail
app.config["MAIL_DEFAULT_SENDER"] = ("Réinitialisation mot de passe", "c4bot.noreply@gmail.com")

mail = Mail(app)

serializer = URLSafeTimedSerializer(app.secret_key)
RESET_TOKEN_SALT = "password-reset-salt"
RESET_TOKEN_MAX_AGE = 1800  # 30 minutes


# Database file
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("PRAGMA user_version")
    version = cursor.fetchone()[0]

    if version < 1:
        # Drop any legacy tables and recreate with the new structure
        cursor.execute("DROP TABLE IF EXISTS user")
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute(
            """
            CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pseudo TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        version = 1
        cursor.execute("PRAGMA user_version = 1")

    # Version 2 introduces the user_stats table storing gameplay statistics.
    if version < 2:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_stats (
                user_id INTEGER PRIMARY KEY,
                best_pendu_streak INTEGER DEFAULT 0,
                pendu_current_streak INTEGER DEFAULT 0,
                c4_ai_wins INTEGER DEFAULT 0,
                c4_ai_losses INTEGER DEFAULT 0,
                c4_online_elo INTEGER DEFAULT 1200,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
            );
            """
        )
        cursor.execute(
            """
            INSERT OR IGNORE INTO user_stats (user_id)
            SELECT id FROM user
            """
        )
        cursor.execute("PRAGMA user_version = 2")
        version = 2
    else:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_stats (
                user_id INTEGER PRIMARY KEY,
                best_pendu_streak INTEGER DEFAULT 0,
                pendu_current_streak INTEGER DEFAULT 0,
                c4_ai_wins INTEGER DEFAULT 0,
                c4_ai_losses INTEGER DEFAULT 0,
                c4_online_elo INTEGER DEFAULT 1200,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
            );
            """
        )
        cursor.execute(
            """
            INSERT OR IGNORE INTO user_stats (user_id)
            SELECT id FROM user
            """
        )

    conn.commit()

    # Ensure Tetris high score column exists (schema version 3)
    cursor.execute("PRAGMA table_info(user_stats)")
    columns = [row[1] for row in cursor.fetchall()]
    if "tetris_high_score" not in columns:
        cursor.execute(
            "ALTER TABLE user_stats ADD COLUMN tetris_high_score INTEGER DEFAULT 0"
        )
        conn.commit()
        cursor.execute("PRAGMA user_version = 3")
        conn.commit()
    elif cursor.execute("PRAGMA user_version").fetchone()[0] < 3:
        cursor.execute("PRAGMA user_version = 3")
        conn.commit()

    # Ensure Tetris online Elo column exists (schema version 4)
    cursor.execute("PRAGMA table_info(user_stats)")
    columns = [row[1] for row in cursor.fetchall()]
    if "tetris_online_elo" not in columns:
        cursor.execute(
            "ALTER TABLE user_stats ADD COLUMN tetris_online_elo INTEGER DEFAULT 1200"
        )
        conn.commit()
        cursor.execute("PRAGMA user_version = 4")
        conn.commit()
    elif cursor.execute("PRAGMA user_version").fetchone()[0] < 4:
        cursor.execute("PRAGMA user_version = 4")
        conn.commit()

    conn.close()


# Initialize DB at startup
init_db()


# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _coerce_password_hash(raw):
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode("utf-8")
    return str(raw).encode("utf-8")


# --- User statistics helpers ---

def get_user_id(pseudo: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM user WHERE pseudo = ?", (pseudo,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def ensure_user_stats(pseudo: str):
    user_id = get_user_id(pseudo)
    if user_id is None:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT OR IGNORE INTO user_stats (user_id)
        VALUES (?)
        """,
        (user_id,),
    )
    conn.commit()
    cursor.execute(
        """
        SELECT
            best_pendu_streak,
            pendu_current_streak,
            c4_ai_wins,
            c4_ai_losses,
            c4_online_elo,
            COALESCE(tetris_high_score, 0),
            COALESCE(tetris_online_elo, 1200)
        FROM user_stats
        WHERE user_id = ?
        """,
        (user_id,),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {
            "best_pendu_streak": 0,
            "pendu_current_streak": 0,
            "c4_ai_wins": 0,
            "c4_ai_losses": 0,
            "c4_online_elo": 1200,
            "tetris_high_score": 0,
            "tetris_online_elo": 1200,
        }
    return {
        "best_pendu_streak": row[0],
        "pendu_current_streak": row[1],
        "c4_ai_wins": row[2],
        "c4_ai_losses": row[3],
        "c4_online_elo": row[4],
        "tetris_high_score": row[5],
        "tetris_online_elo": row[6] if len(row) > 6 else 1200,
    }


def update_user_stats(pseudo: str, **fields):
    if not fields:
        return
    user_id = get_user_id(pseudo)
    if user_id is None:
        return
    ensure_user_stats(pseudo)
    assignments = ", ".join(f"{key} = ?" for key in fields.keys())
    values = list(fields.values())
    values.append(user_id)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE user_stats SET {assignments}, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
        values,
    )
    conn.commit()
    conn.close()


def get_user_elo(pseudo: str) -> int:
    stats = ensure_user_stats(pseudo)
    return stats.get("c4_online_elo", 1200) if stats else 1200


def get_tetris_elo(pseudo: str) -> int:
    stats = ensure_user_stats(pseudo)
    return stats.get("tetris_online_elo", 1200) if stats else 1200


def update_pendu_streak(pseudo: str, won: bool):
    stats = ensure_user_stats(pseudo)
    if not stats:
        return
    current = stats.get("pendu_current_streak", 0)
    best = stats.get("best_pendu_streak", 0)
    if won:
        current += 1
        if current > best:
            best = current
    else:
        current = 0
    update_user_stats(
        pseudo,
        pendu_current_streak=current,
        best_pendu_streak=best,
    )


def adjust_c4_ai_score(pseudo: str, victory: bool):
    stats = ensure_user_stats(pseudo)
    if not stats:
        return
    wins = stats.get("c4_ai_wins", 0)
    losses = stats.get("c4_ai_losses", 0)
    if victory:
        wins += 1
    else:
        losses += 1
    update_user_stats(pseudo, c4_ai_wins=wins, c4_ai_losses=losses)


ELO_K_FACTOR = 32


def calculate_elo_updates(ratings, *, winner=None, draw=False, k_factor=ELO_K_FACTOR):
    ratings = ratings or {}
    players = list(ratings.keys())
    if len(players) < 2:
        return {pseudo: {"before": rating, "after": rating, "delta": 0} for pseudo, rating in ratings.items()}

    if draw:
        scores = {pseudo: 0.5 for pseudo in players}
    else:
        scores = {pseudo: (1.0 if pseudo == winner else 0.0) for pseudo in players}

    updates = {}
    for pseudo in players:
        opponent = next((p for p in players if p != pseudo), None)
        if opponent is None:
            updates[pseudo] = {"before": ratings[pseudo], "after": ratings[pseudo], "delta": 0}
            continue
        expected = 1 / (1 + 10 ** ((ratings[opponent] - ratings[pseudo]) / 400))
        delta = round(k_factor * (scores[pseudo] - expected))
        updates[pseudo] = {
            "before": ratings[pseudo],
            "after": ratings[pseudo] + delta,
            "delta": delta,
        }
    return updates


def apply_multiplayer_result(room, *, winner=None, loser=None, draw=False, reason="normal"):
    players = list(room.get("players", {}).keys())
    if len(players) < 2:
        return {"ratings": {}}

    ratings_before = {}
    for pseudo in players:
        info = room["players"].setdefault(pseudo, {})
        rating = info.get("elo")
        if rating is None:
            rating = get_user_elo(pseudo)
            info["elo"] = rating
        ratings_before[pseudo] = rating

    rating_updates = calculate_elo_updates(ratings_before, winner=winner, draw=draw)

    for pseudo, data in rating_updates.items():
        room["players"][pseudo]["elo"] = data["after"]
        update_user_stats(pseudo, c4_online_elo=data["after"])

    return {
        "ratings": rating_updates,
        "winner": winner,
        "loser": loser,
        "draw": draw,
        "reason": reason,
    }


# --- Jeu du pendu ---
# --- Jeu du pendu ---
MAX_PENDU_ATTEMPTS = 10
PENDU_FOLDER = os.path.join(app.root_path, "templates", "pendu")
PENDU_WORD_SANITIZE_REGEX = re.compile(r"[^A-Za-zÀ-ÖØ-öø-ÿ' -]")
PENDU_DEFAULT_WORDS = [
    "PYTHON",
    "FLASK",
    "ALGORITHME",
    "ORDINATEUR",
    "DEVELOPPEMENT",
    "INTELLIGENCE",
    "PROGRAMMATION",
    "LOGICIEL",
    "BASE DE DONNEES",
    "VARIABLE",
]


def load_pendu_words():
    words = []

    if os.path.isdir(PENDU_FOLDER):
        for entry in sorted(os.listdir(PENDU_FOLDER)):
            if not entry.lower().endswith(".txt"):
                continue

            file_path = os.path.join(PENDU_FOLDER, entry)
            try:
                with open(file_path, encoding="utf-8") as fh:
                    for raw_line in fh:
                        cleaned = PENDU_WORD_SANITIZE_REGEX.sub("", raw_line.strip())
                        cleaned = re.sub(r"\s+", " ", cleaned).strip().upper()
                        if cleaned and any(ch.isalpha() for ch in cleaned):
                            words.append(cleaned)
            except OSError:
                continue

    if not words:
        words = PENDU_DEFAULT_WORDS[:]

    # Supprime les doublons tout en conservant l'ordre
    unique_words = []
    seen = set()
    for word in words:
        if word not in seen:
            unique_words.append(word)
            seen.add(word)

    return unique_words


def start_new_pendu_game():
    words = load_pendu_words()
    chosen_word = random.choice(words)

    session.setdefault("pendu_score", 0)
    session["pendu_game"] = {
        "word": chosen_word,
        "guessed_letters": [],
        "remaining_attempts": MAX_PENDU_ATTEMPTS,
        "status": "playing",
    }
    session.modified = True
    return session["pendu_game"]


def get_pendu_state():
    state = session.get("pendu_game")
    if not state:
        state = start_new_pendu_game()
    session.setdefault("pendu_score", 0)
    return state


def serialize_pendu_state(state):
    word = state.get("word", "")
    guessed_letters = [letter.upper() for letter in state.get("guessed_letters", [])]
    guessed_set = set(guessed_letters)
    remaining_attempts = state.get("remaining_attempts", MAX_PENDU_ATTEMPTS)
    status = state.get("status", "playing")

    display_letters = []
    for char in word:
        if char.isalpha():
            display_letters.append(char if char in guessed_set else "_")
        else:
            display_letters.append(char)

    masked_word = " ".join(display_letters)
    target_letters = {char for char in word if char.isalpha()}
    attempted_letters = guessed_letters
    correct_letters = [letter for letter in attempted_letters if letter in target_letters]
    incorrect_letters = [letter for letter in attempted_letters if letter not in target_letters]

    reveal_word = word if status != "playing" else None

    return {
        "masked_word": masked_word,
        "remaining_attempts": remaining_attempts,
        "max_attempts": MAX_PENDU_ATTEMPTS,
        "status": status,
        "attempted_letters": attempted_letters,
        "correct_letters": correct_letters,
        "incorrect_letters": incorrect_letters,
        "score": session.get("pendu_score", 0),
        "solution": reveal_word,
        "pseudo": session.get("pseudo"),
    }


def process_pendu_guess(letter):
    state = get_pendu_state()
    pseudo = session.get("pseudo")

    if state["status"] != "playing":
        return state, "La partie est terminée. Lancez une nouvelle partie pour continuer."

    normalized_letter = letter.strip().upper()
    if not normalized_letter or len(normalized_letter) != 1 or not normalized_letter.isalpha():
        return state, "Veuillez proposer une lettre valide."

    if normalized_letter in state["guessed_letters"]:
        return state, f"La lettre {normalized_letter} a déjà été testée."

    state["guessed_letters"].append(normalized_letter)

    if normalized_letter not in state["word"]:
        state["remaining_attempts"] = max(0, state["remaining_attempts"] - 1)
        if state["remaining_attempts"] == 0:
            state["status"] = "lost"
            session["pendu_score"] = 0
            if pseudo:
                update_pendu_streak(pseudo, won=False)
    else:
        word_letters = {char for char in state["word"] if char.isalpha()}
        if word_letters.issubset(set(state["guessed_letters"])):
            state["status"] = "won"
            session["pendu_score"] = session.get("pendu_score", 0) + 1
            if pseudo:
                update_pendu_streak(pseudo, won=True)

    session.modified = True
    return state, None


def create_user(pseudo: str, email: str, password: str):
    password_hash = hash_password(password)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM user WHERE pseudo = ?", (pseudo,))
        if cursor.fetchone():
            return False, "pseudo_taken"

        cursor.execute("SELECT 1 FROM user WHERE email = ?", (email,))
        if cursor.fetchone():
            return False, "email_taken"

        cursor.execute(
            "INSERT INTO user (pseudo, email, password_hash) VALUES (?, ?, ?)",
            (pseudo, email, password_hash),
        )
        conn.commit()
        ensure_user_stats(pseudo)
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def verify_user(pseudo: str, password: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM user WHERE pseudo = ?", (pseudo,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return False
    stored_hash = _coerce_password_hash(row["password_hash"])
    if not stored_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except ValueError:
        return False


def get_user_by_email(email: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_id(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def update_user_password(user_id: int, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE user SET password_hash = ? WHERE id = ?",
        (hash_password(password), user_id),
    )
    conn.commit()
    conn.close()


def generate_reset_token(user_id: int) -> str:
    return serializer.dumps({"user_id": user_id}, salt=RESET_TOKEN_SALT)


def verify_reset_token(token: str):
    try:
        data = serializer.loads(token, salt=RESET_TOKEN_SALT, max_age=RESET_TOKEN_MAX_AGE)
        return data.get("user_id")
    except SignatureExpired:
        return "expired"
    except BadSignature:
        return None


def send_reset_email(user):
    token = generate_reset_token(user["id"])
    reset_url = url_for("reset_password", token=token, _external=True)
    msg = Message(
        subject="Réinitialisation de votre mot de passe",
        recipients=[user["email"]],
    )
    msg.body = (
        f"Bonjour {user['pseudo']},\n\n"
        f"Vous avez demandé la réinitialisation de votre mot de passe.\n"
        f"Cliquez sur le lien suivant (valide 30 minutes) pour en définir un nouveau :\n"
        f"{reset_url}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez ce message."
    )
    msg.html = render_template(
        "emails/reset_password.html",
        pseudo=user["pseudo"],
        reset_url=reset_url,
    )
    try:
        mail.send(msg)
    except Exception as exc:
        app.logger.error("Erreur lors de l'envoi de l'email de réinitialisation: %s", exc)

# --- Auth endpoints ---
from flask import jsonify, request, session

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    pseudo = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    password2 = data.get("password2", "")

    if not pseudo or not email or not password:
        return jsonify({"ok": False, "error": "missing_fields"}), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({"ok": False, "error": "invalid_email"}), 400

    if password != password2:
        return jsonify({"ok": False, "error": "password_mismatch"}), 400

    ok, err = create_user(pseudo, email, password)
    if not ok:
        if err == "pseudo_taken":
            return jsonify({"ok": False, "error": "pseudo_taken"}), 400
        if err == "email_taken":
            return jsonify({"ok": False, "error": "email_taken"}), 400
        return jsonify({"ok": False, "error": "db_error", "detail": err}), 500

    # auto-login after register
    session["username"] = pseudo
    session["pseudo"] = pseudo
    return jsonify({"ok": True, "username": pseudo})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"ok": False, "error": "missing_fields"}), 400

    if not verify_user(username, password):
        return jsonify({"ok": False, "error": "invalid_credentials"}), 401

    session["username"] = username
    session["pseudo"] = username
    return jsonify({"ok": True, "username": username, "redirect": url_for("menu")})


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    message = None
    status = None

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            message = "Veuillez indiquer votre adresse email."
            status = "error"
        elif not EMAIL_REGEX.match(email):
            message = "Adresse email invalide."
            status = "error"
        else:
            user = get_user_by_email(email)
            if user:
                send_reset_email(user)
            message = "Si un compte existe, un lien de réinitialisation a été envoyé."
            status = "success"

    return render_template("forgot_password.html", message=message, status=status)


@app.route("/reset", defaults={"token": None}, methods=["GET"])
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    message = None
    status = None

    if not token:
        return redirect(url_for("forgot_password"))

    user_id = verify_reset_token(token)
    if user_id == "expired":
        return render_template(
            "reset_password.html",
            token=None,
            message="Ce lien a expiré. Veuillez refaire une demande de réinitialisation.",
            status="error",
        )

    if user_id is None:
        return render_template(
            "reset_password.html",
            token=None,
            message="Lien de réinitialisation invalide.",
            status="error",
        )

    user = get_user_by_id(user_id)
    if not user:
        return render_template(
            "reset_password.html",
            token=None,
            message="Utilisateur introuvable.",
            status="error",
        )

    if request.method == "POST":
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not password:
            message = "Veuillez saisir un nouveau mot de passe."
            status = "error"
        elif password != password2:
            message = "Les mots de passe ne correspondent pas."
            status = "error"
        else:
            update_user_password(user_id, password)
            return redirect(
                url_for(
                    "connexion",
                    message="Mot de passe réinitialisé avec succès !",
                    status="success",
                )
            )

    return render_template("reset_password.html", token=token, message=message, status=status)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    best_accept = request.accept_mimetypes.best if request.accept_mimetypes else None
    if request.is_json or best_accept == "application/json":
        return jsonify({"ok": True, "redirect": url_for("connexion")})
    return redirect(url_for("connexion"))

# Choix du bon binaire selon le système
if sys.platform.startswith("win"):
    solver_name = "c4solver.exe"
else:
    solver_name = "c4solver"

# Chemin complet vers le binaire
solver_path = os.path.join(os.path.dirname(__file__), solver_name)

# Sur Linux / macOS : s'assurer que le fichier est exécutable
if not sys.platform.startswith("win"):
    os.chmod(solver_path, os.stat(solver_path).st_mode | stat.S_IEXEC)


# Lancer le processus
solver_process = Popen(
    [solver_path, "-a"],
    stdin=PIPE,
    stdout=PIPE,
    stderr=PIPE,
    text=True,
    bufsize=1
)

time.sleep(1)

joueurs_coups = {}


solver_lock = threading.Lock()


@app.route("/menu")
@login_required
def menu():
    return render_template("menu.html", pseudo=session["pseudo"])


@app.route("/tetris")
@login_required
def tetris():
    pseudo = session["pseudo"]
    stats = ensure_user_stats(pseudo) or {}
    return render_template(
        "tetris/index.html",
        pseudo=pseudo,
        best_score=stats.get("tetris_high_score", 0),
    )


@app.route("/tetris/highscore", methods=["GET", "POST"])
@login_required
def tetris_highscore():
    pseudo = session["pseudo"]
    stats = ensure_user_stats(pseudo) or {}
    if request.method == "GET":
        return jsonify({"score": stats.get("tetris_high_score", 0)})

    data = request.get_json(silent=True) or {}
    new_score = data.get("score")
    try:
        new_score = int(new_score)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_score"}), 400

    if new_score < 0:
        return jsonify({"error": "invalid_score"}), 400

    current_score = stats.get("tetris_high_score", 0)
    if new_score <= current_score:
        return jsonify({"score": current_score})

    user_id = get_user_id(pseudo)
    if user_id is None:
        return jsonify({"error": "user_not_found"}), 404

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE user_stats SET tetris_high_score = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
        (new_score, user_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"score": new_score})


@app.route("/profile")
@login_required
def profile():
    pseudo = session["pseudo"]
    stats = ensure_user_stats(pseudo) or {}
    status = session.pop("profile_status", {})
    return render_template(
        "profile.html",
        pseudo=pseudo,
        best_pendu_streak=stats.get("best_pendu_streak", 0),
        current_pendu_streak=stats.get("pendu_current_streak", 0),
        c4_ai_wins=stats.get("c4_ai_wins", 0),
        c4_ai_losses=stats.get("c4_ai_losses", 0),
        c4_online_elo=stats.get("c4_online_elo", 1200),
        tetris_high_score=stats.get("tetris_high_score", 0),
        tetris_online_elo=stats.get("tetris_online_elo", 1200),
        profile_status=status,
    )


@app.route("/profile/settings", methods=["POST"])
@login_required
def profile_settings():
    pseudo = session["pseudo"]
    action = request.form.get("action")
    status = {"category": "error", "message": "Une erreur est survenue."}

    if action == "change_pseudo":
        new_pseudo = (request.form.get("new_pseudo") or "").strip()
        if not new_pseudo:
            status = {"category": "error", "message": "Merci d'indiquer un nouveau pseudo."}
        elif len(new_pseudo) < 3:
            status = {"category": "error", "message": "Le pseudo doit contenir au moins 3 caractères."}
        elif new_pseudo == pseudo:
            status = {"category": "success", "message": "Ton pseudo est déjà à jour."}
        else:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM user WHERE pseudo = ?", (new_pseudo,))
                if cursor.fetchone():
                    status = {"category": "error", "message": "Ce pseudo est déjà utilisé."}
                else:
                    engaged = False
                    _, room = find_room_for_player(pseudo)
                    if room:
                        engaged = True
                    with tetris_lock:
                        if tetris_player_active_room.get(pseudo):
                            engaged = True
                        lobby_id, _ = _tetris_find_lobby_for_player(pseudo)
                        if lobby_id:
                            engaged = True
                    if engaged:
                        status = {"category": "error", "message": "Quitte tes parties en cours avant de changer de pseudo."}
                    else:
                        cursor.execute("UPDATE user SET pseudo = ? WHERE pseudo = ?", (new_pseudo, pseudo))
                        conn.commit()
                        for sid, name in list(connected_users.items()):
                            if name == pseudo:
                                connected_users[sid] = new_pseudo
                        session["pseudo"] = new_pseudo
                        pseudo = new_pseudo
                        status = {"category": "success", "message": "Pseudo mis à jour."}
            finally:
                conn.close()

    elif action == "change_password":
        current_password = (request.form.get("current_password") or "").strip()
        new_password = (request.form.get("new_password") or "").strip()
        confirm_password = (request.form.get("confirm_password") or "").strip()
        if not current_password or not new_password or not confirm_password:
            status = {"category": "error", "message": "Merci de compléter tous les champs."}
        elif new_password != confirm_password:
            status = {"category": "error", "message": "Les nouveaux mots de passe ne correspondent pas."}
        elif len(new_password) < 8:
            status = {"category": "error", "message": "Le nouveau mot de passe doit contenir au moins 8 caractères."}
        else:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash FROM user WHERE pseudo = ?", (pseudo,))
                row = cursor.fetchone()
                stored_hash = _coerce_password_hash(row[0] if row else None)
                if not stored_hash or not bcrypt.checkpw(current_password.encode("utf-8"), stored_hash):
                    status = {"category": "error", "message": "L'ancien mot de passe est incorrect."}
                else:
                    new_hash = hash_password(new_password)
                    cursor.execute("UPDATE user SET password_hash = ? WHERE pseudo = ?", (new_hash, pseudo))
                    conn.commit()
                    status = {"category": "success", "message": "Mot de passe mis à jour."}
            finally:
                conn.close()
    else:
        status = {"category": "error", "message": "Action inconnue."}

    session["profile_status"] = status
    return redirect(url_for("profile"))


@app.route("/pendu")
@login_required
def pendu():
    state = serialize_pendu_state(get_pendu_state())
    return render_template("pendu/index.html", pendu_state=state)


@app.route("/pendu/state")
@login_required
def pendu_state():
    state = serialize_pendu_state(get_pendu_state())
    return jsonify({"state": state})


@app.route("/pendu/deviner", methods=["POST"])
@login_required
def pendu_guess():
    data = request.get_json(silent=True) or {}
    letter = data.get("letter", "")
    state, message = process_pendu_guess(letter)
    payload = {"state": serialize_pendu_state(state)}
    if message:
        payload["message"] = message
    return jsonify(payload)


@app.route("/pendu/nouvelle-partie", methods=["POST"])
@login_required
def pendu_new_game():
    start_new_pendu_game()
    return jsonify({"state": serialize_pendu_state(get_pendu_state())})


@app.route("/lobby")
@login_required
def lobby():
    return render_template("C4/lobby.html", pseudo=session["pseudo"])


# --- Gestion du mode multijoueur ---
rooms_lock = threading.Lock()
rooms_multi = {}
player_rooms = {}
next_room_id = 1


# --- Gestion du mode Tetris ---
tetris_lock = threading.Lock()
tetris_queue = []  # legacy queue (unused with lobby mode, kept for cleanup)
tetris_rooms = {}
tetris_sid_to_room = {}
tetris_lobbies = {}
tetris_player_to_lobby = {}
tetris_player_active_room = {}
tetris_lobby_sid_map = {}
tetris_next_room_id = 1
TETRIS_PIECES = ["I", "J", "L", "O", "S", "T", "Z"]
TETRIS_SPEED_SCHEDULE = [
    {"time": 0, "interval": 1000},
    {"time": 45, "interval": 850},
    {"time": 90, "interval": 700},
    {"time": 135, "interval": 580},
    {"time": 180, "interval": 480},
    {"time": 240, "interval": 380},
]
TETRIS_START_DELAY_MS = 3000


def _tetris_new_bag():
    bag = TETRIS_PIECES[:]
    random.shuffle(bag)
    return bag


def _tetris_draw_pieces(room, count):
    pieces = []
    while len(pieces) < count:
        if not room.get("bag"):
            room["bag"] = _tetris_new_bag()
        pieces.append(room["bag"].pop())
    room.setdefault("sequence", []).extend(pieces)
    return pieces


def _tetris_room_from_sid(sid):
    room_id = tetris_sid_to_room.get(sid)
    if not room_id:
        return None, None
    return room_id, tetris_rooms.get(room_id)


def _tetris_get_opponent(room, pseudo):
    if not room:
        return None, None
    for name, info in room.get("players", {}).items():
        if name != pseudo:
            return info.get("sid"), name
    return None, None


def _tetris_remove_from_queue(sid):
    for idx, entry in enumerate(list(tetris_queue)):
        if entry.get("sid") == sid:
            tetris_queue.pop(idx)
            return True
    return False


def _tetris_find_lobby_for_player(pseudo):
    if not pseudo:
        return None, None
    room_id = tetris_player_to_lobby.get(pseudo)
    if not room_id:
        return None, None
    return room_id, tetris_lobbies.get(room_id)


def _tetris_remove_player_from_lobby(room_id, pseudo, *, reason="leave"):
    lobby = tetris_lobbies.get(room_id)
    if not lobby or pseudo not in lobby.get("players", {}):
        return False
    player_info = lobby["players"].pop(pseudo, {})
    tetris_player_to_lobby.pop(pseudo, None)
    sid = player_info.get("sid")
    if sid:
        tetris_lobby_sid_map.pop(sid, None)
    if lobby.get("host") == pseudo:
        lobby["host"] = next(iter(lobby["players"]), None)
    if lobby["players"]:
        lobby["status"] = "waiting"
    else:
        tetris_lobbies.pop(room_id, None)
    return True


def _tetris_finish_room(room_id, *, winner=None, loser=None, reason="top_out", draw=False):
    room = tetris_rooms.get(room_id)
    if not room:
        return
    if room.get("status") == "finished":
        return
    room["status"] = "finished"
    players = room.get("players", {})
    scores = room.get("scores", {})
    lines = room.get("lines", {})
    ratings_before = {}
    for pseudo in players.keys():
        info = players.setdefault(pseudo, {})
        rating = info.get("elo")
        if rating is None:
            rating = get_tetris_elo(pseudo)
            info["elo"] = rating
        ratings_before[pseudo] = rating
    rating_updates = calculate_elo_updates(ratings_before, winner=winner, draw=draw)
    payload_template = {
        "room_id": room_id,
        "winner": winner,
        "loser": loser,
        "draw": draw,
        "reason": reason,
    }
    for pseudo, info in players.items():
        sid = info.get("sid")
        if not sid:
            continue
        opponent_sid, opponent_name = _tetris_get_opponent(room, pseudo)
        rating_data = rating_updates.get(pseudo, {"before": info.get("elo"), "after": info.get("elo"), "delta": 0})
        opponent_rating = None
        opponent_delta = 0
        if opponent_name:
            opponent_rating = rating_updates.get(opponent_name, {}).get("after", players.get(opponent_name, {}).get("elo"))
            opponent_delta = rating_updates.get(opponent_name, {}).get("delta", 0)
        payload = payload_template.copy()
        payload.update(
            {
                "your_score": scores.get(pseudo, 0),
                "your_lines": lines.get(pseudo, 0),
                "opponent": opponent_name,
                "opponent_score": scores.get(opponent_name, 0) if opponent_name else 0,
                "opponent_lines": lines.get(opponent_name, 0) if opponent_name else 0,
                "your_elo": rating_data.get("after"),
                "your_elo_delta": rating_data.get("delta", 0),
                "opponent_elo": opponent_rating,
                "opponent_elo_delta": opponent_delta,
            }
        )
        socketio.emit("tetris_match_result", payload, room=sid)
        socketio.emit("tetris_queue_status", {"status": "idle"}, room=sid)
        tetris_sid_to_room.pop(sid, None)
        tetris_player_active_room.pop(pseudo, None)
        update_user_stats(pseudo, tetris_online_elo=rating_data.get("after", ratings_before.get(pseudo, 1200)))
    tetris_rooms.pop(room_id, None)


def _tetris_emit_ready_state(room):
    if not room:
        return
    ready_map = room.setdefault("ready", {})
    payload_ready = {name: bool(ready_map.get(name)) for name in room.get("players", {})}
    for pseudo, info in room.get("players", {}).items():
        sid = info.get("sid")
        if not sid:
            continue
        socketio.emit(
            "tetris_ready_state",
            {"room_id": room.get("id"), "ready": payload_ready, "you": pseudo},
            room=sid,
        )


def _tetris_begin_countdown(room):
    if not room:
        return
    status = room.get("status")
    if status not in {"waiting", "countdown"}:
        return
    room["status"] = "active"
    room["start_time"] = time.time() + (TETRIS_START_DELAY_MS / 1000.0)
    payload = {
        "room_id": room.get("id"),
        "start_in": TETRIS_START_DELAY_MS,
        "speed_schedule": room.get("speed_schedule", []),
    }
    for info in room.get("players", {}).values():
        sid = info.get("sid")
        if sid:
            socketio.emit("tetris_match_start", payload, room=sid)
    ready_map = room.setdefault("ready", {})
    for name in list(ready_map.keys()):
        ready_map[name] = False


def _tetris_start_match(player_a, player_b, room_id=None):
    room_id = room_id or uuid.uuid4().hex[:8]
    rating_a = player_a.get("elo") or get_tetris_elo(player_a["pseudo"])
    rating_b = player_b.get("elo") or get_tetris_elo(player_b["pseudo"])
    room = {
        "id": room_id,
        "players": {
            player_a["pseudo"]: {"sid": player_a["sid"], "alive": True, "elo": rating_a},
            player_b["pseudo"]: {"sid": player_b["sid"], "alive": True, "elo": rating_b},
        },
        "bag": [],
        "sequence": [],
        "scores": {
            player_a["pseudo"]: 0,
            player_b["pseudo"]: 0,
        },
        "lines": {
            player_a["pseudo"]: 0,
            player_b["pseudo"]: 0,
        },
        "alive": {
            player_a["pseudo"]: True,
            player_b["pseudo"]: True,
        },
        "created": time.time(),
        "start_time": None,
        "speed_schedule": list(TETRIS_SPEED_SCHEDULE),
        "status": "waiting",
        "ready": {
            player_a["pseudo"]: False,
            player_b["pseudo"]: False,
        },
    }
    room["boards"] = {}
    tetris_rooms[room_id] = room
    tetris_sid_to_room[player_a["sid"]] = room_id
    tetris_sid_to_room[player_b["sid"]] = room_id
    tetris_player_active_room[player_a["pseudo"]] = room_id
    tetris_player_active_room[player_b["pseudo"]] = room_id

    initial_pieces = _tetris_draw_pieces(room, 40)
    for current, opponent in ((player_a, player_b), (player_b, player_a)):
        socketio.emit(
            "tetris_match_found",
            {
                "room_id": room_id,
                "opponent": opponent["pseudo"],
                "pieces": list(initial_pieces),
                "speed_schedule": room["speed_schedule"],
                "your_elo": current.get("elo", get_tetris_elo(current["pseudo"])),
                "opponent_elo": opponent.get("elo", get_tetris_elo(opponent["pseudo"])),
            },
            room=current["sid"],
        )
        socketio.emit(
            "tetris_queue_status",
            {"status": "matched", "room_id": room_id, "opponent": opponent["pseudo"]},
            room=current["sid"],
        )

    _tetris_emit_ready_state(room)


def _tetris_cleanup_sid(sid, *, disconnect=False, pseudo=None):
    with tetris_lock:
        lobby_room_id = tetris_lobby_sid_map.pop(sid, None)
        if lobby_room_id:
            lobby = tetris_lobbies.get(lobby_room_id)
            if not pseudo and lobby:
                for name, info in lobby.get("players", {}).items():
                    if info.get("sid") == sid:
                        pseudo = name
                        break
            if pseudo:
                _tetris_remove_player_from_lobby(
                    lobby_room_id,
                    pseudo,
                    reason="disconnect" if disconnect else "leave",
                )
                lobby = tetris_lobbies.get(lobby_room_id)
                if lobby:
                    for info in lobby.get("players", {}).values():
                        if info.get("sid"):
                            socketio.emit(
                                "tetris_queue_status",
                                {"status": "waiting", "room_id": lobby_room_id},
                                room=info["sid"],
                            )
            if not disconnect:
                socketio.emit("tetris_queue_status", {"status": "idle"}, room=sid)
            return
        if _tetris_remove_from_queue(sid):
            if not disconnect:
                socketio.emit("tetris_queue_status", {"status": "idle"}, room=sid)
            return
        room_id, room = _tetris_room_from_sid(sid)
        if not room_id or not room:
            return
        if not pseudo:
            for name, info in room.get("players", {}).items():
                if info.get("sid") == sid:
                    pseudo = name
                    break
        if not pseudo:
            return
        opponent_sid, opponent_name = _tetris_get_opponent(room, pseudo)
        room["alive"][pseudo] = False
        reason = "disconnect" if disconnect else "forfeit"
        _tetris_finish_room(room_id, winner=opponent_name, loser=pseudo, reason=reason)


def create_empty_board():
    return [[0 for _ in range(7)] for _ in range(6)]


def clone_board(board):
    return [row[:] for row in board]


def check_victory(board, row, col, token):
    directions = [(1, 0), (0, 1), (1, 1), (1, -1)]
    for dr, dc in directions:
        count = 1
        for step in (1, -1):
            r, c = row + dr * step, col + dc * step
            while 0 <= r < 6 and 0 <= c < 7 and board[r][c] == token:
                count += 1
                r += dr * step
                c += dc * step
        if count >= 4:
            return True
    return False


def board_full(board):
    return all(cell != 0 for row in board for cell in row)


def forfeit_room(room_id, loser, departing_sid=None):
    with rooms_lock:
        room = rooms_multi.get(room_id)
        if not room or loser not in room["players"]:
            return False
        opponent = next((p for p in room["players"] if p != loser), None)
        board_copy = clone_board(room["board"])
        result_info = None
        if opponent:
            result_info = apply_multiplayer_result(
                room,
                winner=opponent,
                loser=loser,
                draw=False,
                reason="forfeit",
            )
        room["status"] = "finished"
        room["turn"] = None
        room["reset_votes"] = set()
        room["reset_context"] = "rematch"
        players_snapshot = {
            name: {
                "sid": info.get("sid"),
                "color": info.get("color"),
                "elo": info.get("elo"),
            }
            for name, info in room["players"].items()
        }
        rooms_multi.pop(room_id, None)

    payload = {
        "board": board_copy,
        "column": None,
        "row": None,
        "played_by": None,
        "color": None,
        "next_turn": None,
        "winner": opponent,
        "draw": False,
        "forfeit": loser,
        "result": result_info,
    }
    socketio.emit("move_played", payload, room=room_id)

    for name, info in players_snapshot.items():
        sid = info.get("sid")
        if sid:
            player_rooms.pop(sid, None)
            leave_room(room_id, sid=sid)

    if departing_sid:
        player_rooms.pop(departing_sid, None)

    return True


def dissolve_room(room_id, departing_pseudo=None, departing_sid=None, notify=True):
    with rooms_lock:
        room = rooms_multi.pop(room_id, None)
    if not room:
        return False

    if departing_sid:
        leave_room(room_id, sid=departing_sid)

    for pseudo, info in room["players"].items():
        sid = info.get("sid")
        if not sid:
            continue
        player_rooms.pop(sid, None)
        if sid != departing_sid:
            leave_room(room_id, sid=sid)
        if notify and pseudo != departing_pseudo:
            socketio.emit("opponent_left", {"pseudo": departing_pseudo}, room=sid)
    return True


def find_room_for_player(pseudo):
    with rooms_lock:
        for room_id, room in rooms_multi.items():
            if pseudo in room["players"]:
                return room_id, room
    return None, None

@app.route("/admin")
@login_required
def admin_panel():
    pseudo = session.get("pseudo", "").lower()
    if not is_admin_name(pseudo):
        print('Access denied for user:', session.get("pseudo"))
        return redirect(url_for("lobby"))
    print('Access granted for admin user:', session.get("pseudo"))
    return render_template("C4/admin.html", pseudo=session["pseudo"])


@app.route("/lobby_multi")
@login_required
def lobby_multi():
    return render_template("C4/lobby_multi.html", pseudo=session["pseudo"])


@app.route("/multi/<room_id>")
@login_required
def multi(room_id):
    pseudo = session["pseudo"]
    with rooms_lock:
        room = rooms_multi.get(room_id)
        if not room or pseudo not in room["players"]:
            return redirect(url_for("lobby_multi"))
    return render_template("C4/multi.html", pseudo=pseudo, room_id=room_id)


@app.route("/api/rooms", methods=["GET"])
@login_required
def list_rooms():
    pseudo = session["pseudo"]
    with rooms_lock:
        rooms = []
        for room_id, room in rooms_multi.items():
            rooms.append({
                "id": room_id,
                "host": room["host"],
                "players": list(room["players"].keys()),
                "status": room["status"],
                "is_owner": room["host"] == pseudo
            })
    return jsonify({"rooms": rooms})


@app.route("/api/rooms", methods=["POST"])
@login_required
def create_room():
    global next_room_id
    pseudo = session["pseudo"]

    existing_room_id, _ = find_room_for_player(pseudo)
    if existing_room_id:
        return jsonify({"ok": False, "error": "already_in_room", "room_id": existing_room_id}), 400

    with rooms_lock:
        room_id = f"room-{next_room_id}"
        next_room_id += 1
        rooms_multi[room_id] = {
            "host": pseudo,
            "players": {
                pseudo: {
                    "color": "rouge",
                    "sid": None,
                    "elo": get_user_elo(pseudo),
                }
            },
            "order": [pseudo],
            "status": "waiting",
            "board": create_empty_board(),
            "turn": None,
            "reset_votes": set(),
            "reset_context": None,
        }

    return jsonify({"ok": True, "room_id": room_id})


@app.route("/api/rooms/<room_id>/join", methods=["POST"])
@login_required
def join_room_multi(room_id):
    pseudo = session["pseudo"]

    existing_room_id, _ = find_room_for_player(pseudo)
    if existing_room_id:
        if existing_room_id == room_id:
            return jsonify({"ok": True, "room_id": room_id})
        return jsonify({"ok": False, "error": "already_in_room", "room_id": existing_room_id}), 400

    with rooms_lock:
        room = rooms_multi.get(room_id)
        if not room:
            return jsonify({"ok": False, "error": "room_not_found"}), 404
        if room["status"] not in ("waiting", "ready"):
            return jsonify({"ok": False, "error": "room_unavailable"}), 400
        if len(room["players"]) >= 2:
            return jsonify({"ok": False, "error": "room_full"}), 400

        room["players"][pseudo] = {
            "color": "jaune",
            "sid": None,
            "elo": get_user_elo(pseudo),
        }
        room["order"].append(pseudo)
        room["status"] = "ready"

    return jsonify({"ok": True, "room_id": room_id})



@app.route("/api/tetris/rooms", methods=["GET"])
@login_required
def tetris_list_rooms():
    pseudo = session["pseudo"]
    with tetris_lock:
        rooms = []
        for room_id, lobby in tetris_lobbies.items():
            rooms.append(
                {
                    "id": room_id,
                    "host": lobby.get("host"),
                    "players": list(lobby.get("players", {}).keys()),
                    "status": lobby.get("status", "waiting"),
                }
            )
        active_room_id = tetris_player_active_room.get(pseudo)
        current_lobby_id = tetris_player_to_lobby.get(pseudo)
    return jsonify(
        {
            "rooms": rooms,
            "active_room_id": active_room_id,
            "lobby_room_id": current_lobby_id,
        }
    )


@app.route("/api/tetris/rooms", methods=["POST"])
@login_required
def tetris_create_room():
    pseudo = session["pseudo"]
    with tetris_lock:
        if tetris_player_active_room.get(pseudo):
            return (
                jsonify({"ok": False, "error": "already_in_match", "room_id": tetris_player_active_room[pseudo]}),
                400,
            )
        current_room_id, _ = _tetris_find_lobby_for_player(pseudo)
        if current_room_id:
            return jsonify({"ok": False, "error": "already_in_room", "room_id": current_room_id}), 400
        global tetris_next_room_id
        room_id = f"tetris-{tetris_next_room_id}"
        tetris_next_room_id += 1
        tetris_lobbies[room_id] = {
            "id": room_id,
            "host": pseudo,
            "players": {
                pseudo: {"sid": None, "elo": get_tetris_elo(pseudo)},
            },
            "status": "waiting",
            "created": time.time(),
        }
        tetris_player_to_lobby[pseudo] = room_id
    return jsonify({"ok": True, "room_id": room_id})


@app.route("/api/tetris/rooms/<room_id>/join", methods=["POST"])
@login_required
def tetris_join_room_http(room_id):
    pseudo = session["pseudo"]
    with tetris_lock:
        if tetris_player_active_room.get(pseudo):
            return (
                jsonify({"ok": False, "error": "already_in_match", "room_id": tetris_player_active_room[pseudo]}),
                400,
            )
        current_room_id, _ = _tetris_find_lobby_for_player(pseudo)
        if current_room_id:
            if current_room_id == room_id:
                return jsonify({"ok": True, "room_id": room_id})
            return jsonify({"ok": False, "error": "already_in_room", "room_id": current_room_id}), 400
        lobby = tetris_lobbies.get(room_id)
        if not lobby:
            return jsonify({"ok": False, "error": "room_not_found"}), 404
        if lobby.get("status") not in ("waiting", "ready"):
            return jsonify({"ok": False, "error": "room_unavailable"}), 400
        if len(lobby.get("players", {})) >= 2:
            return jsonify({"ok": False, "error": "room_full"}), 400
        lobby.setdefault("players", {})[pseudo] = {"sid": None, "elo": get_tetris_elo(pseudo)}
        lobby["status"] = "ready" if len(lobby["players"]) >= 2 else "waiting"
        if lobby.get("host") is None:
            lobby["host"] = pseudo
        tetris_player_to_lobby[pseudo] = room_id
    return jsonify({"ok": True, "room_id": room_id})


@app.route("/api/tetris/rooms/<room_id>/leave", methods=["POST"])
@login_required
def tetris_leave_room_http(room_id):
    pseudo = session["pseudo"]
    with tetris_lock:
        lobby = tetris_lobbies.get(room_id)
        if not lobby or pseudo not in lobby.get("players", {}):
            return jsonify({"ok": False, "error": "room_not_found"}), 404
        sid = lobby["players"][pseudo].get("sid")
        _tetris_remove_player_from_lobby(room_id, pseudo, reason="leave")
        if sid:
            socketio.emit("tetris_queue_status", {"status": "idle"}, room=sid)
        lobby = tetris_lobbies.get(room_id)
        if lobby:
            lobby["status"] = "waiting"
            for info in lobby.get("players", {}).values():
                other_sid = info.get("sid")
                if other_sid:
                    socketio.emit(
                        "tetris_queue_status",
                        {"status": "waiting", "room_id": room_id},
                        room=other_sid,
                    )
    return jsonify({"ok": True})


@app.route('/set_pseudo', methods=['POST'])
def set_pseudo():
    pseudo = request.form.get('pseudo')
    if pseudo:
        session['pseudo'] = pseudo
        return redirect(url_for('menu'))
    return redirect(url_for('index'))


@app.route('/jeu')
@login_required
def jeu():
    if 'pseudo' not in session:
        return redirect(url_for('connexion'))

    session['coups'] = ""
    pseudo_courant = session['pseudo']
    joueurs_coups[pseudo_courant] = ""


    pseudo_courant = session['pseudo']
    top10 = []
    score_pseudo = None

    try:
        with open("scores.json", "r") as f:
            scores = json.load(f)

        
        scores_trie = sorted(scores.items(), key=lambda x: x[1]["victoires"], reverse=True)
        top10 = scores_trie[:10]

 
        if pseudo_courant not in dict(top10):
            score_pseudo = scores.get(pseudo_courant)

    except Exception as e:
        print("Erreur chargement scores :", e)

    return render_template("C4/index.html", pseudo=pseudo_courant, top10=top10, joueur_score=score_pseudo)

@app.route('/reset', methods=['POST'])
def reset_partie():
    session["coups"] = ""

    return jsonify({"message": "Partie réinitialisée."})


@app.route('/')
def connexion():
    message = request.args.get('message')
    status = request.args.get('status')
    response = make_response(
        render_template(
            'connexion.html',
            initial_message=message,
            initial_status=status,
        )
    )
    response.headers['ngrok-skip-browser-warning'] = 'true'
    return response

@app.route('/images/icon.png')
def serve_image(filename):
    return send_from_directory('images', filename)

@app.route('/stats/<pseudo>')
def stats(pseudo):
    try:
        with open("scores.json", "r") as f:
            scores = json.load(f)
        return jsonify(scores.get(pseudo, {"victoires": 0, "defaites": 0}))
    except:
        return jsonify({"error": "Fichier introuvable"}), 500


def convertir_plateau(plateau):
    if len(plateau) != 42:
        raise ValueError("Le plateau doit contenir exactement 42 caractères")

    plateau = plateau[::-1]
    coups = ""
    for j in range(5,-1,-1):
        for i in range(7*j, 7*(j+1)):
            if plateau[i] != '0':
                coups += str(abs(6 - i % 7) + 1)
    return coups[::1]

def envoyer_sequence(sequence):
    global solver_process, solver_lock
    print("Envoyé au solver :", sequence)
    with solver_lock:
        if solver_process.poll() is not None:
            raise Exception("Le solver s'est arrêté.")

        solver_process.stdin.write(sequence + "\n")
        solver_process.stdin.flush()

        
        while True:
            ligne = solver_process.stdout.readline()

            if ligne.startswith("info") or ligne.strip() != "":
                return ligne.strip()

def convertir_en_grille(sequence):
    grille = [[0]*7 for _ in range(6)]
    joueur = 1
    for c in sequence:
        col = int(c) - 1
        for row in reversed(range(6)):
            if grille[row][col] == 0:
                grille[row][col] = joueur
                break
        joueur = 3 - joueur
    return grille


def mettre_a_jour_scores(pseudo, victoire_ia):
    chemin = "scores.json"
    scores = {}

    if os.path.exists(chemin):
        with open(chemin, "r") as f:
            scores = json.load(f)

    if pseudo not in scores:
        scores[pseudo] = {"victoires": 0, "defaites": 0}

    if victoire_ia:
        scores[pseudo]["defaites"] += 1
    else:
        scores[pseudo]["victoires"] += 1

    if pseudo:
        adjust_c4_ai_score(pseudo, victory=not victoire_ia)

    with open(chemin, "w") as f:
        json.dump(scores, f, indent=2)

    trier_scores()

def trier_scores():
    chemin = "scores.json"
    scores = {}

    if os.path.exists(chemin):
        with open(chemin, "r") as f:
            scores = json.load(f)

    scores_trie = sorted(scores.items(), key=lambda x: x[1]["defaites"])

    with open(chemin, "w") as f:
        json.dump(dict(scores_trie), f, indent=2)

@app.route('/fin', methods=['POST'])
def fin_partie():
    data = request.json
    pseudo = data.get("pseudo", "Invité")
    gagnant = data.get("gagnant") 

    if gagnant == "egalite":
        return jsonify({"message": "Égalité – aucun score mis à jour."})

    mettre_a_jour_scores(pseudo, gagnant == "ia")
    return jsonify({"message": "Score mis à jour."})


@app.route('/jouer', methods=['POST'])
def jouer():
    data = request.json
    coup_joueur = data.get("coup")
    
    if "coups" not in session:
        session["coups"] = ""

  
    if coup_joueur != None : 
        session["coups"] += str(coup_joueur + 1)

    
    try:

        response = envoyer_sequence(session["coups"])
        if coup_joueur != None :
            scores = list(map(int, response.strip().split()[1:]))
        else :
            scores = list(map(int, response.strip().split()))
        meilleures_colonnes = [i for i, val in enumerate(scores) if val == max(scores)]
        coup_ia = meilleures_colonnes[0]

        session["coups"] += str(coup_ia + 1)

        joueurs_coups[session["pseudo"]] = session["coups"]

        for sid, suivi in spectateurs.items():
            if suivi == session.get("pseudo"):
                socketio.emit("etat_grille", {
                    "grille": convertir_en_grille(session["coups"])
                }, room=sid)
        
        time.sleep(0.5)

        return jsonify({"colonne": coup_ia})

    except Exception as e:
        print("Erreur lors de l'envoi au solver :", e)
        return jsonify({"error": str(e)}), 500

######## PARTIE ADMIN AVEC WEBSOCKET ########

connected_users = {}  # sid -> pseudo

def is_admin_name(name: str) -> bool:
    if not name:
        return False
    return name.lower() in ("admin")  # accepte plusieurs alias

def get_admin_sids():
    return [sid for sid, pseudo in connected_users.items() if is_admin_name(pseudo)]

@socketio.on('connect')
def handle_connect():
    # demande au client de s'identifier
    emit('demande_pseudo')

@socketio.on('pseudo')
def handle_pseudo(pseudo):
    # Enregistre le pseudo pour ce sid
    connected_users[request.sid] = pseudo
    print(f"{pseudo} connecté (sid={request.sid})")

    # Envoie la liste complète des pseudos aux admins connectés
    users = list(connected_users.values())
    admin_sids = get_admin_sids()
    if admin_sids:
        for sid in admin_sids:
            socketio.emit('update_users', users, room=sid)
    # Optionnel : si tu veux que tous les admins voient en "broadcast", on a déjà ciblé ci-dessus.
    return {"ok": True}

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    pseudo = connected_users.pop(sid, "inconnu")
    print(f"{pseudo} déconnecté (sid={sid})")
    _tetris_cleanup_sid(sid, disconnect=True, pseudo=pseudo)

    room_id = player_rooms.get(sid)
    if room_id:
        with rooms_lock:
            room = rooms_multi.get(room_id)
            status = room.get("status") if room else None
        if room and status == "playing" and pseudo != "inconnu":
            forfeit_room(room_id, pseudo, departing_sid=sid)
            player_rooms.pop(sid, None)
        else:
            player_rooms.pop(sid, None)
            dissolve_room(room_id, departing_pseudo=pseudo, departing_sid=sid)

    # Met à jour la liste envoyée aux admins restants
    users = list(connected_users.values())
    admin_sids = get_admin_sids()
    if admin_sids:
        for sid in admin_sids:
            socketio.emit('update_users', users, room=sid)

@socketio.on("etat_grille")
def maj_grille(data):
    pseudo = data.get("pseudo")
    grille = data.get("grille")
    joueurs_coups[pseudo] = "".join(
        str(c + 1) for c in range(7) for r in range(6) if grille[r][c] != 0
    )
    for sid, suivi in spectateurs.items():
        if suivi == pseudo:
            socketio.emit("etat_grille", {"grille": grille}, room=sid)

@socketio.on("reset_grille")
def handle_reset_grille(pseudo):
    print("resetting")
    for sid, suivi in spectateurs.items():
        if suivi == pseudo:
            socketio.emit("etat_grille", {
                "grille": [[0]*7 for _ in range(6)]
            }, room=sid)


@socketio.on("spectateur")
def handle_spectateur(pseudo_suivi):
    sid = request.sid
    print(f"[Spectateur] {sid} observe {pseudo_suivi}")
    spectateurs[sid] = pseudo_suivi

    coups = joueurs_coups.get(pseudo_suivi, "")
    grille = convertir_en_grille(coups) if coups else [[0]*7 for _ in range(6)]

    socketio.emit("etat_grille", {"grille": grille}, room=sid)


spectateurs = {}


@app.route('/spectateur/<pseudo>')
@login_required
def spectateur(pseudo):
    return render_template('C4/spectateur.html', joueur=pseudo)


@socketio.on('register_player')
def register_player(data):
    room_id = data.get("room_id")
    pseudo = connected_users.get(request.sid)
    if not room_id or not pseudo:
        emit("room_error", {"message": "identification_incomplete"})
        return

    waiting_payload = None
    start_payloads = []

    with rooms_lock:
        room = rooms_multi.get(room_id)
        if not room or pseudo not in room["players"]:
            emit("room_error", {"message": "room_not_found"})
            return

        info = room["players"][pseudo]
        info["sid"] = request.sid
        info.setdefault("elo", get_user_elo(pseudo))
        join_room(room_id)
        player_rooms[request.sid] = room_id
        total_players = len(room["players"])
        display_total = max(2, total_players)

        if len(room["players"]) < 2:
            waiting_payload = {
                "color": info["color"],
                "board": clone_board(room["board"]),
                "your_elo": info["elo"],
                "total": display_total,
            }
        else:
            all_connected = all(pdata.get("sid") for pdata in room["players"].values())
            if all_connected:
                room["board"] = create_empty_board()
                board_copy = clone_board(room["board"])
                room["turn"] = room["order"][0]
                room["status"] = "playing"
                room["reset_votes"] = set()
                room["reset_context"] = None
                for pseudo_player, pdata in room["players"].items():
                    opponent = [p for p in room["players"] if p != pseudo_player][0]
                    start_payloads.append({
                        "sid": pdata.get("sid"),
                        "payload": {
                            "room_id": room_id,
                            "board": board_copy,
                            "color": pdata["color"],
                            "you": pseudo_player,
                            "opponent": opponent,
                            "your_turn": room["turn"] == pseudo_player,
                            "your_elo": pdata.get("elo", get_user_elo(pseudo_player)),
                            "opponent_elo": room["players"][opponent].get("elo", get_user_elo(opponent)),
                            "total": display_total,
                        }
                    })
            else:
                waiting_payload = {
                    "color": info["color"],
                    "board": clone_board(room["board"]),
                    "your_elo": info["elo"],
                    "total": display_total,
                }

    if waiting_payload:
        emit("waiting_player", waiting_payload)
    for item in start_payloads:
        if item["sid"]:
            socketio.emit("game_start", item["payload"], room=item["sid"])


@socketio.on('play_move')
def play_move(data):
    room_id = data.get("room_id")
    column = data.get("column")
    pseudo = connected_users.get(request.sid)

    if room_id is None or pseudo is None:
        emit("room_error", {"message": "identification_incomplete"})
        return

    move_payload = None
    error_payload = None

    with rooms_lock:
        room = rooms_multi.get(room_id)
        if not room or pseudo not in room["players"]:
            error_payload = {"message": "room_not_found"}
        elif room["status"] != "playing":
            error_payload = {"message": "game_not_active"}
        elif room["turn"] != pseudo:
            error_payload = {"message": "not_your_turn"}
        else:
            try:
                column = int(column)
            except (TypeError, ValueError):
                error_payload = {"message": "invalid_column"}
            else:
                if not 0 <= column < 7:
                    error_payload = {"message": "invalid_column"}
                else:
                    board = room["board"]
                    token = 1 if room["players"][pseudo]["color"] == "rouge" else 2
                    row_played = None
                    for row in range(5, -1, -1):
                        if board[row][column] == 0:
                            board[row][column] = token
                            row_played = row
                            break
                    if row_played is None:
                        error_payload = {"message": "column_full"}
                    else:
                        opponent = next((p for p in room["players"] if p != pseudo), None)
                        winner = check_victory(board, row_played, column, token)
                        draw = board_full(board)
                        result_info = None
                        if winner:
                            room["status"] = "finished"
                            room["turn"] = None
                            room["reset_votes"] = set()
                            room["reset_context"] = "rematch"
                            result_info = apply_multiplayer_result(
                                room,
                                winner=pseudo,
                                loser=opponent,
                                draw=False,
                                reason="victory",
                            )
                        elif draw:
                            room["status"] = "finished"
                            room["turn"] = None
                            room["reset_votes"] = set()
                            room["reset_context"] = "rematch"
                            result_info = apply_multiplayer_result(
                                room,
                                winner=None,
                                loser=None,
                                draw=True,
                                reason="draw",
                            )
                        else:
                            next_player = [p for p in room["players"] if p != pseudo][0]
                            room["turn"] = next_player
                            room["reset_votes"] = set()
                            room["reset_context"] = None
                        move_payload = {
                            "board": clone_board(board),
                            "column": column,
                            "row": row_played,
                            "played_by": pseudo,
                            "color": room["players"][pseudo]["color"],
                            "next_turn": room["turn"],
                            "winner": pseudo if winner else None,
                            "draw": draw and not winner,
                            "result": result_info,
                        }

    if error_payload:
        emit("move_rejected", error_payload)
    elif move_payload:
        socketio.emit("move_played", move_payload, room=room_id)


@socketio.on('reset_multiplayer')
def reset_multiplayer(data):
    room_id = data.get("room_id") if isinstance(data, dict) else None
    pseudo = connected_users.get(request.sid)

    if room_id is None or pseudo is None:
        emit("room_error", {"message": "identification_incomplete"})
        return

    responses = []
    broadcast_vote = None

    with rooms_lock:
        room = rooms_multi.get(room_id)
        if not room or pseudo not in room["players"]:
            emit("room_error", {"message": "room_not_found"})
            return

        total_players = len(room["players"])
        display_total = max(2, total_players)
        if total_players < 2:
            emit("room_error", {"message": "not_enough_players"})
            return

        votes = room.setdefault("reset_votes", set())
        context = "rematch" if room.get("status") == "finished" else "reset"
        room["reset_context"] = context
        votes.add(pseudo)
        vote_count = len(votes)
        broadcast_vote = {
            "votes": vote_count,
            "total": display_total,
            "context": context,
        }

        if vote_count == total_players:
            room["board"] = create_empty_board()
            board_copy = clone_board(room["board"])
            connected_players = {
                name: info for name, info in room["players"].items() if info.get("sid")
            }
            if len(connected_players) == total_players:
                room["status"] = "playing"
                room["turn"] = room["order"][0]
                room["reset_votes"] = set()
                room["reset_context"] = None
                next_turn = room["turn"]
                for name, info in room["players"].items():
                    sid = info.get("sid")
                    if not sid:
                        continue
                    opponent = next((p for p in room["players"] if p != name), None)
                    payload = {
                        "room_id": room_id,
                        "board": clone_board(board_copy),
                        "color": info["color"],
                        "opponent": opponent,
                        "your_turn": next_turn == name,
                        "next_turn": next_turn,
                        "your_elo": info.get("elo", get_user_elo(name)),
                        "opponent_elo": room["players"].get(opponent, {}).get("elo", get_user_elo(opponent)) if opponent else None,
                        "total": display_total,
                    }
                    responses.append(("game_reset", sid, payload))
            else:
                room["status"] = "waiting"
                room["turn"] = None
                room["reset_votes"] = set()
                for name, info in room["players"].items():
                    sid = info.get("sid")
                    if not sid:
                        continue
                    payload = {
                        "color": info["color"],
                        "board": clone_board(board_copy),
                        "your_elo": info.get("elo", get_user_elo(name)),
                        "total": display_total,
                    }
                    responses.append(("waiting_player", sid, payload))

    if broadcast_vote:
        socketio.emit("reset_vote_update", broadcast_vote, room=room_id)
    for event_name, sid, payload in responses:
        socketio.emit(event_name, payload, room=sid)


@socketio.on('leave_multiplayer')
def leave_multiplayer(data):
    pseudo = connected_users.get(request.sid)
    room_id = player_rooms.get(request.sid)
    if room_id:
        with rooms_lock:
            room = rooms_multi.get(room_id)
            status = room.get("status") if room else None
        if room and status == "playing" and pseudo:
            forfeit_room(room_id, pseudo, departing_sid=request.sid)
            player_rooms.pop(request.sid, None)
        else:
            player_rooms.pop(request.sid, None)
            dissolve_room(room_id, departing_pseudo=pseudo, departing_sid=request.sid)
    emit("left_room", {"ok": True})


# --- Événements Socket.IO : Tetris ---


@socketio.on('tetris_find_match')
def tetris_find_match():
    sid = request.sid
    pseudo = connected_users.get(sid)
    if not pseudo:
        emit('tetris_error', {'message': 'unknown_player'})
        return
    with tetris_lock:
        room_id, room = _tetris_room_from_sid(sid)
        if room_id and room:
            emit('tetris_queue_status', {'status': 'matched', 'room_id': room_id}, room=sid)
            return
        if any(entry.get('sid') == sid for entry in tetris_queue):
            emit('tetris_queue_status', {'status': 'searching'}, room=sid)
            return
        tetris_queue.append({'sid': sid, 'pseudo': pseudo})
        emit('tetris_queue_status', {'status': 'searching'}, room=sid)
        if len(tetris_queue) >= 2:
            player_a = tetris_queue.pop(0)
            player_b = tetris_queue.pop(0)
            _tetris_start_match(player_a, player_b)


@socketio.on('tetris_cancel_matchmaking')
def tetris_cancel_matchmaking():
    sid = request.sid
    with tetris_lock:
        removed = _tetris_remove_from_queue(sid)
        room_id, room = _tetris_room_from_sid(sid)
    if removed:
        emit('tetris_queue_status', {'status': 'idle'})
    elif room_id and room:
        emit('tetris_queue_status', {'status': 'matched', 'room_id': room_id})
    else:
        emit('tetris_queue_status', {'status': 'idle'})


@socketio.on('tetris_join_room')
def tetris_join_room(data):
    sid = request.sid
    pseudo = connected_users.get(sid)
    if not pseudo:
        emit('tetris_error', {'message': 'unknown_player'})
        return
    room_id = None
    if isinstance(data, dict):
        room_id = data.get('room_id')
    if not room_id:
        emit('tetris_error', {'message': 'invalid_room'})
        return
    with tetris_lock:
        lobby = tetris_lobbies.get(room_id)
        if not lobby:
            room = tetris_rooms.get(room_id)
            if room and pseudo in room.get('players', {}):
                info = room['players'][pseudo]
                info['sid'] = sid
                tetris_sid_to_room[sid] = room_id
                tetris_player_active_room[pseudo] = room_id
                emit('tetris_queue_status', {'status': 'matched', 'room_id': room_id}, room=sid)
                _tetris_emit_ready_state(room)
            else:
                emit('tetris_error', {'message': 'room_not_found'})
            return
        if pseudo not in lobby.get('players', {}):
            emit('tetris_error', {'message': 'not_in_room'})
            return
        lobby_info = lobby['players'][pseudo]
        lobby_info['sid'] = sid
        lobby_info['elo'] = get_tetris_elo(pseudo)
        tetris_lobby_sid_map[sid] = room_id
        lobby['status'] = 'ready' if len(lobby['players']) >= 2 else 'waiting'
        opponent_name = next((name for name in lobby['players'] if name != pseudo), None)
        ready_players = []
        for name, info in lobby['players'].items():
            if not info.get('sid'):
                ready_players = None
                break
            ready_players.append({
                'pseudo': name,
                'sid': info.get('sid'),
                'elo': info.get('elo') or get_tetris_elo(name),
            })
        if ready_players and len(ready_players) == 2:
            tetris_lobbies.pop(room_id, None)
            for name, info in lobby['players'].items():
                tetris_player_to_lobby.pop(name, None)
                sid_existing = info.get('sid')
                if sid_existing:
                    tetris_lobby_sid_map.pop(sid_existing, None)
            _tetris_start_match(ready_players[0], ready_players[1], room_id=room_id)
        else:
            emit(
                'tetris_queue_status',
                {
                    'status': lobby.get('status', 'waiting'),
                    'room_id': room_id,
                    'opponent': opponent_name,
                },
                room=sid,
            )
            for name, info in lobby['players'].items():
                other_sid = info.get('sid')
                if other_sid and other_sid != sid:
                    socketio.emit(
                        'tetris_queue_status',
                        {
                            'status': lobby.get('status', 'waiting'),
                            'room_id': room_id,
                            'opponent': pseudo,
                        },
                        room=other_sid,
                    )


@socketio.on('tetris_set_ready')
def tetris_set_ready(data):
    sid = request.sid
    pseudo = connected_users.get(sid)
    if not pseudo:
        return
    desired = False
    if isinstance(data, dict) and 'ready' in data:
        desired = bool(data.get('ready'))
    with tetris_lock:
        room_id, room = _tetris_room_from_sid(sid)
        if not room_id or not room:
            emit('tetris_error', {'message': 'not_in_room'})
            return
        status = room.get('status')
        if status not in {'waiting', 'countdown', 'active'}:
            emit('tetris_error', {'message': 'invalid_state'})
            return
        if status not in {'waiting', 'countdown'}:
            return
        room.setdefault('ready', {})[pseudo] = desired
        _tetris_emit_ready_state(room)
        if room.get('status') == 'waiting' and all(
            room['ready'].get(name) for name in room.get('players', {})
        ):
            _tetris_begin_countdown(room)


@socketio.on('tetris_leave_match')
def tetris_leave_match():
    sid = request.sid
    pseudo = connected_users.get(sid)
    _tetris_cleanup_sid(sid, pseudo=pseudo)
    emit('tetris_left', {'ok': True})


@socketio.on('tetris_request_pieces')
def tetris_request_pieces(data):
    sid = request.sid
    room_id, room = _tetris_room_from_sid(sid)
    if not room_id or not room:
        return
    count = data.get('count') if isinstance(data, dict) else None
    try:
        count = int(count)
    except (TypeError, ValueError):
        count = 14
    count = max(1, min(count, 70))
    with tetris_lock:
        if room_id not in tetris_rooms:
            return
        pieces = _tetris_draw_pieces(room, count)
        for info in room.get('players', {}).values():
            target_sid = info.get('sid')
            if target_sid:
                socketio.emit('tetris_add_pieces', {'room_id': room_id, 'pieces': list(pieces)}, room=target_sid)


@socketio.on('tetris_board_update')
def tetris_board_update(data):
    sid = request.sid
    pseudo = connected_users.get(sid)
    if not pseudo:
        return
    room_id, room = _tetris_room_from_sid(sid)
    if not room_id or not room:
        return
    board = data.get('board') if isinstance(data, dict) else None
    score_value = data.get('score') if isinstance(data, dict) else None
    lines_value = data.get('lines') if isinstance(data, dict) else None
    if not isinstance(board, list):
        board = None
    try:
        score = int(score_value)
    except (TypeError, ValueError):
        score = room.get('scores', {}).get(pseudo, 0)
    try:
        lines = int(lines_value)
    except (TypeError, ValueError):
        lines = room.get('lines', {}).get(pseudo, 0)
    with tetris_lock:
        if room.get('status') != 'active':
            return
        room.setdefault('boards', {})[pseudo] = board
        room['scores'][pseudo] = score
        room['lines'][pseudo] = lines
        opponent_sid, opponent_name = _tetris_get_opponent(room, pseudo)
    if opponent_sid:
        socketio.emit(
            'tetris_opponent_board',
            {
                'room_id': room_id,
                'board': board,
                'score': score,
                'lines': lines,
                'opponent': pseudo,
            },
            room=opponent_sid,
        )


@socketio.on('tetris_game_over')
def tetris_game_over(data):
    sid = request.sid
    pseudo = connected_users.get(sid)
    if not pseudo:
        return
    room_id, room = _tetris_room_from_sid(sid)
    if not room_id or not room:
        return
    score_value = data.get('score') if isinstance(data, dict) else 0
    lines_value = data.get('lines') if isinstance(data, dict) else 0
    board = data.get('board') if isinstance(data, dict) else None
    reason = data.get('reason') if isinstance(data, dict) else 'top_out'
    try:
        score = int(score_value)
    except (TypeError, ValueError):
        score = 0
    try:
        lines = int(lines_value)
    except (TypeError, ValueError):
        lines = 0
    if not isinstance(board, list):
        board = None
    with tetris_lock:
        if room.get('status') == 'finished':
            return
        room['scores'][pseudo] = score
        room['lines'][pseudo] = lines
        room['alive'][pseudo] = False
        if board is not None:
            room.setdefault('boards', {})[pseudo] = board
        opponent_sid, opponent_name = _tetris_get_opponent(room, pseudo)
        if opponent_sid:
            socketio.emit(
                'tetris_opponent_game_over',
                {
                    'room_id': room_id,
                    'opponent': pseudo,
                    'score': score,
                    'lines': lines,
                },
                room=opponent_sid,
            )
        all_finished = all(not alive for alive in room.get('alive', {}).values())
        if not all_finished:
            return
        players = list(room.get('players', {}).keys())
        scores = room.get('scores', {})
        winner = None
        loser = None
        draw = False
        if len(players) >= 2:
            ordered = sorted(players, key=lambda name: scores.get(name, 0), reverse=True)
            best = ordered[0]
            second = ordered[1]
            best_score = scores.get(best, 0)
            second_score = scores.get(second, 0)
            if best_score == second_score:
                draw = True
            else:
                winner = best
                loser = second
        else:
            draw = True
        final_reason = reason if reason in {'forfeit', 'disconnect'} else 'score'
        _tetris_finish_room(room_id, winner=winner, loser=loser, reason=final_reason, draw=draw)

@socketio.on("demande_video")
def handle_demande_video(data):
    to = data["to"]
    print(f"[DEMANDE VIDEO] Vers {to}")
    for sid, pseudo in connected_users.items():
        print(f"SocketID: {sid} -> {pseudo}")
        if pseudo == to:
            socketio.emit("demande_video", data, room=sid)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
