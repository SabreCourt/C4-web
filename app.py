from flask import Flask, request, jsonify, render_template, send_from_directory, make_response, redirect, url_for, session
from subprocess import Popen, PIPE
from flask_socketio import SocketIO, emit
import os
import json
import time
import threading

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps
from flask import redirect, url_for, session

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "pseudo" not in session:
            return redirect(url_for("accueil"))
        return f(*args, **kwargs)
    return decorated_function

# --- Auth config ---
if 'app' not in globals():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

socketio = SocketIO(app)


# Database file
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

# Initialize DB at startup
init_db()

# Helper functions
def create_user(username, password):
    password_hash = generate_password_hash(password)
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        return True, None
    except sqlite3.IntegrityError as e:
        return False, "username_taken"
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()

def verify_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    return check_password_hash(row[0], password)

# --- Auth endpoints ---
from flask import jsonify, request, session

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    password2 = data.get("password2", "")
    if not username or not password:
        return jsonify({"ok": False, "error": "missing_fields"}), 400
    if password != password2:
        return jsonify({"ok": False, "error": "password_mismatch"}), 400
    ok, err = create_user(username, password)
    if not ok:
        if err == "username_taken":
            return jsonify({"ok": False, "error": "username_taken"}), 400
        return jsonify({"ok": False, "error": "db_error", "detail": err}), 500
    # auto-login after register
    session["username"] = username
    session["pseudo"] = username
    return jsonify({"ok": True, "username": username})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    print(username + " logged in")
    if not username or not password:
        return jsonify({"ok": False, "error": "missing_fields"}), 400
    if verify_user(username, password):
        session["username"] = username
        session["pseudo"] = username
    return jsonify({"ok": True, "username": username, "redirect": "/lobby"})


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("username", None)
    return jsonify({"ok": True})


# Démarrage du solver en mode interactif
from subprocess import Popen, PIPE
import os, stat

# Chemin absolu ou relatif vers le binaire Linux
solver_path = os.path.join(os.path.dirname(__file__), "c4solver")

if not os.access(solver_path, os.X_OK):
    os.chmod(solver_path, os.stat(solver_path).st_mode | stat.S_IEXEC)

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
    return render_template("lobby.html", pseudo=session["pseudo"])

@app.route("/admin")
@login_required
def admin_panel():
    pseudo = session.get("pseudo", "").lower()
    if not is_admin_name(pseudo):
        print('Access denied for user:', session.get("pseudo"))
        return redirect(url_for("lobby"))
    print('Access granted for admin user:', session.get("pseudo"))
    return render_template("admin.html", pseudo=session["pseudo"])



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
        return redirect(url_for('accueil'))

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

    return render_template("index.html", pseudo=pseudo_courant, top10=top10, joueur_score=score_pseudo)

@app.route('/reset', methods=['POST'])
def reset_partie():
    session["coups"] = ""

    return jsonify({"message": "Partie réinitialisée."})


@app.route('/')
def accueil():
    response = make_response(render_template('accueil.html'))
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

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    pseudo = connected_users.pop(sid, "inconnu")
    print(f"{pseudo} déconnecté (sid={sid})")

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
    return render_template('spectateur.html', joueur=pseudo)

@socketio.on("offer")
def handle_offer(data):
    to = data["to"]
    print(f"🚀 Offre reçue de {data['from']} pour {data['to']}")

    for sid, pseudo in connected_users.items():
        if pseudo == to:
            socketio.emit("offer", data, room=sid)

@socketio.on("answer")
def handle_answer(data):
    to = data["to"]
    for sid, pseudo in connected_users.items():
        if pseudo == to:
            socketio.emit("answer", data, room=sid)

@socketio.on("candidate")
def handle_candidate(data):
    to = data["to"]
    for sid, pseudo in connected_users.items():
        if pseudo == to:
            socketio.emit("candidate", data, room=sid)

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

