from flask import Flask, request, jsonify, render_template, send_from_directory, make_response, redirect, url_for, session
from subprocess import Popen, PIPE
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os
import json
import time
import threading
import sys
import stat
import re


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
        cursor.execute("PRAGMA user_version = 1")
    else:
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='user'"
        )
        if not cursor.fetchone():
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

    conn.commit()
    conn.close()


# Initialize DB at startup
init_db()


# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


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
    try:
        return bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode("utf-8"))
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
        "C4/emails/reset_password.html",
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
    return jsonify({"ok": True, "username": username, "redirect": "/lobby"})


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

    return render_template("C4/forgot_password.html", message=message, status=status)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    message = None
    status = None

    user_id = verify_reset_token(token)
    if user_id == "expired":
        return render_template(
            "C4/reset_password.html",
            token=None,
            message="Ce lien a expiré. Veuillez refaire une demande de réinitialisation.",
            status="error",
        )

    if user_id is None:
        return render_template(
            "C4/reset_password.html",
            token=None,
            message="Lien de réinitialisation invalide.",
            status="error",
        )

    user = get_user_by_id(user_id)
    if not user:
        return render_template(
            "C4/reset_password.html",
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

    return render_template("C4/reset_password.html", token=token, message=message, status=status)


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


@app.route("/lobby")
@login_required
def lobby():
    return render_template("C4/lobby.html", pseudo=session["pseudo"])


# --- Gestion du mode multijoueur ---
rooms_lock = threading.Lock()
rooms_multi = {}
player_rooms = {}
next_room_id = 1


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
            "players": {pseudo: {"color": "rouge", "sid": None}},
            "order": [pseudo],
            "status": "waiting",
            "board": create_empty_board(),
            "turn": None
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

        room["players"][pseudo] = {"color": "jaune", "sid": None}
        room["order"].append(pseudo)
        room["status"] = "ready"

    return jsonify({"ok": True, "room_id": room_id})



@app.route('/set_pseudo', methods=['POST'])
def set_pseudo():
    pseudo = request.form.get('pseudo')
    if pseudo:
        session['pseudo'] = pseudo  
        return redirect(url_for('lobby'))
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
            'C4/connexion.html',
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

    room_id = player_rooms.pop(sid, None)
    if room_id:
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
        join_room(room_id)
        player_rooms[request.sid] = room_id

        if len(room["players"]) < 2:
            waiting_payload = {
                "color": info["color"],
                "board": clone_board(room["board"])
            }
        else:
            all_connected = all(pdata.get("sid") for pdata in room["players"].values())
            if all_connected:
                room["board"] = create_empty_board()
                board_copy = clone_board(room["board"])
                room["turn"] = room["order"][0]
                room["status"] = "playing"
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
                            "your_turn": room["turn"] == pseudo_player
                        }
                    })
            else:
                waiting_payload = {
                    "color": info["color"],
                    "board": clone_board(room["board"])
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
                        winner = check_victory(board, row_played, column, token)
                        draw = board_full(board)
                        if winner:
                            room["status"] = "finished"
                            room["turn"] = None
                        elif draw:
                            room["status"] = "finished"
                            room["turn"] = None
                        else:
                            next_player = [p for p in room["players"] if p != pseudo][0]
                            room["turn"] = next_player
                        move_payload = {
                            "board": clone_board(board),
                            "column": column,
                            "row": row_played,
                            "played_by": pseudo,
                            "color": room["players"][pseudo]["color"],
                            "next_turn": room["turn"],
                            "winner": pseudo if winner else None,
                            "draw": draw and not winner
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

    with rooms_lock:
        room = rooms_multi.get(room_id)
        if not room or pseudo not in room["players"]:
            emit("room_error", {"message": "room_not_found"})
            return

        room["board"] = create_empty_board()
        board_copy = clone_board(room["board"])

        connected_players = {
            name: info for name, info in room["players"].items() if info.get("sid")
        }

        if len(room["players"]) >= 2 and len(connected_players) == len(room["players"]):
            room["status"] = "playing"
            room["turn"] = room["order"][0]
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
                }
                responses.append(("game_reset", sid, payload))
        else:
            room["status"] = "waiting"
            room["turn"] = None
            for name, info in room["players"].items():
                sid = info.get("sid")
                if not sid:
                    continue
                payload = {
                    "color": info["color"],
                    "board": clone_board(board_copy),
                }
                responses.append(("waiting_player", sid, payload))

    for event_name, sid, payload in responses:
        socketio.emit(event_name, payload, room=sid)


@socketio.on('leave_multiplayer')
def leave_multiplayer(data):
    pseudo = connected_users.get(request.sid)
    room_id = player_rooms.pop(request.sid, None)
    if room_id:
        dissolve_room(room_id, departing_pseudo=pseudo, departing_sid=request.sid)
    emit("left_room", {"ok": True})


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

