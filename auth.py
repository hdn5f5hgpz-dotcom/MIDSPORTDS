import functools
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import sqlite3
import time
from email.message import EmailMessage
from flask import (Blueprint, current_app, flash, g, redirect, render_template, request,
                   session, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from db import get_db

bp = Blueprint("auth", __name__)
ROLES = ("club", "joueur", "agent", "coach")
SPORTS = ("football", "handball", "basketball")

DUREE_CODE = 900          # un code de validation vaut 15 minutes
ESSAIS_CODE = 5           # 5 essais, puis il faut un nouveau code
ATTENTE_RENVOI = 60       # secondes entre deux envois de code
DUREE_LIEN = 3600         # le lien « mot de passe oublié » vaut 1 heure
FENETRE = 900             # fenêtre des limites de tentatives (15 minutes)
DUMMY_HASH = generate_password_hash("mot-de-passe-factice")
_demandes = {}            # limites en mémoire (valables pour 1 processus)
_echecs = {}


def normalise(ident):
    """Adresse e-mail valide en minuscules, sinon None."""
    ident = (ident or "").strip().lower()
    ok = len(ident) <= 120 and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", ident)
    return ident if ok else None


@bp.before_app_request
def charger_utilisateur():
    uid = session.get("user_id")
    g.user = None
    if uid:
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        # un changement de mot de passe ferme toutes les autres sessions ; un compte suspendu est déconnecté
        if user and not user["suspended"] and session.get("pv") == user["password_hash"][-12:]:
            g.user = user
        else:
            session.clear()


def _connecte(view, verifie):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.path))
        if verifie and not g.user["email_verified"]:
            return redirect(url_for("auth.verify"))
        return view(*args, **kwargs)
    return wrapped


def login_required(view):
    """Connecté ET adresse e-mail validée."""
    return _connecte(view, True)


def session_required(view):
    """Connecté, même si l'adresse e-mail n'est pas encore validée."""
    return _connecte(view, False)


def _ouvrir_session(user_id):
    user = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    session.clear()
    session["user_id"] = user_id
    session["pv"] = user["password_hash"][-12:]
    session.permanent = True          # reste connecté, comme Facebook


# ---- e-mails et limites ---------------------------------------------------------------
def envoyer_mail(destinataire, sujet, corps):
    """Envoie un e-mail par SMTP (variables SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, MAIL_FROM).
    Sans SMTP et hors production, le message s'affiche dans la console du serveur."""
    hote = os.environ.get("SMTP_HOST")
    if hote:
        msg = EmailMessage()
        msg["Subject"] = sujet
        msg["From"] = os.environ.get("MAIL_FROM", os.environ.get("SMTP_USER", "no-reply@midsport.local"))
        msg["To"] = destinataire
        msg.set_content(corps)
        port = int(os.environ.get("SMTP_PORT", "587"))
        with (smtplib.SMTP_SSL if port == 465 else smtplib.SMTP)(hote, port, timeout=10) as smtp:
            if port != 465:
                smtp.starttls()
            if os.environ.get("SMTP_USER"):
                smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            smtp.send_message(msg)
    elif not os.environ.get("MIDSPORT_PROD"):
        current_app.logger.warning("[DEV] E-mail pour %s : %s\n%s", destinataire, sujet, corps)


def ip_client():
    """IP du visiteur. Derrière un proxy de confiance (le serveur n'écoute qu'en local),
    définir IP_HEADER : « CF-Connecting-IP » (Cloudflare) ou « X-Forwarded-For » (Tailscale)."""
    nom = os.environ.get("IP_HEADER")
    valeur = request.headers.get(nom, "") if nom else ""
    if valeur:
        return valeur.split(",")[-1].strip()    # dernière entrée = celle ajoutée par notre proxy
    return request.remote_addr


def _compter(table, cle):
    """Enregistre un événement ; retourne le nombre d'événements dans la fenêtre."""
    maintenant = time.time()
    if len(table) > 10000:
        for k in [k for k, v in table.items() if not v or maintenant - v[-1] > FENETRE]:
            del table[k]
    recents = [t for t in table.get(cle, []) if maintenant - t < FENETRE] + [maintenant]
    table[cle] = recents
    return len(recents)


def _nombre(table, cle):
    maintenant = time.time()
    return len([t for t in table.get(cle, []) if maintenant - t < FENETRE])


def _trop_de_demandes(ip, maximum=5):
    return _compter(_demandes, ip) > maximum


# ---- connexion / inscription ----------------------------------------------------------
@bp.route("/connexion", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for("views.accueil"))
    if request.method == "POST":
        ident = normalise(request.form.get("identifier"))
        ip = ip_client()
        cle = (ip, ident or "")
        # 5 erreurs pour un même compte depuis une même IP, ou 30 depuis une même IP : pause de 15 minutes
        if _nombre(_echecs, cle) >= 5 or _nombre(_echecs, (ip, "*")) >= 30:
            flash("Trop de tentatives. Réessayez dans 15 minutes.")
            return render_template("login.html")
        user = None
        if ident:
            user = get_db().execute("SELECT * FROM users WHERE identifier = ?", (ident,)).fetchone()
        valide = check_password_hash(user["password_hash"] if user else DUMMY_HASH,
                                     request.form.get("password", ""))
        # même message dans tous les cas : on ne révèle pas si le compte existe
        if user is None or not valide:
            _compter(_echecs, cle)
            _compter(_echecs, (ip, "*"))
            flash("E-mail ou mot de passe incorrect.")
        elif user["suspended"]:
            flash("Ce compte est suspendu.")
        else:
            _echecs.pop(cle, None)
            _ouvrir_session(user["id"])
            nxt = request.args.get("next", "")
            ok = nxt.startswith("/") and not nxt.startswith("//")
            return redirect(nxt if ok else url_for("views.accueil"))
    return render_template("login.html")


@bp.route("/inscription", methods=("GET", "POST"))
def register():
    if g.user:
        return redirect(url_for("views.accueil"))
    if request.method == "POST":
        role = request.form.get("role")
        name = request.form.get("name", "").strip()
        sport = request.form.get("sport")
        ident = normalise(request.form.get("identifier"))
        pw = request.form.get("password", "")
        erreur = None
        if role not in ROLES:
            erreur = "Choisissez un type de compte."
        elif not name or len(name) > 80:
            erreur = "Saisissez un nom (80 caractères maximum)."
        elif sport not in SPORTS:
            erreur = "Choisissez un sport."
        elif ident is None:
            erreur = "Saisissez une adresse e-mail valide."
        elif len(pw) < 8:
            erreur = "Le mot de passe doit contenir au moins 8 caractères."
        elif not request.form.get("terms"):
            erreur = "Vous devez accepter les conditions d’utilisation."
        if erreur is None:
            conn = get_db()
            try:
                cur = conn.execute(
                    "INSERT INTO users(role,name,sport,identifier,password_hash,terms_at)"
                    " VALUES (?,?,?,?,?,datetime('now'))",
                    (role, name, sport, ident, generate_password_hash(pw)))
                conn.commit()
            except sqlite3.IntegrityError:
                erreur = "Un compte existe déjà avec cet e-mail."
            else:
                _ouvrir_session(cur.lastrowid)
                _envoyer_code(cur.lastrowid, ident)
                return redirect(url_for("auth.verify"))
        flash(erreur)
    return render_template("register.html")


@bp.post("/deconnexion")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


# ---- validation de l'adresse e-mail par code ------------------------------------------
def _hash_code(code):
    cle = current_app.config["SECRET_KEY"].encode()
    return hmac.new(cle, code.encode(), hashlib.sha256).hexdigest()


def _envoyer_code(user_id, email):
    """Crée un code à 6 chiffres (valable 15 min) et l'envoie. Retourne False si l'envoi échoue."""
    code = f"{secrets.randbelow(10 ** 6):06d}"
    now = int(time.time())
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO email_codes(user_id, code_hash, expires_at, attempts, last_sent)"
                 " VALUES (?,?,?,0,?)", (user_id, _hash_code(code), now + DUREE_CODE, now))
    conn.commit()
    try:
        envoyer_mail(email, "Votre code de validation MidSport",
                     f"Votre code de validation : {code}\n\nIl est valable 15 minutes. "
                     "Si vous n’avez pas créé de compte MidSport, ignorez ce message.")
        return True
    except Exception:
        current_app.logger.exception("Échec de l’envoi du code de validation")
        return False


@bp.route("/verification", methods=("GET", "POST"))
@session_required
def verify():
    if g.user["email_verified"]:
        return redirect(url_for("views.accueil"))
    if request.method == "POST":
        code = re.sub(r"\D", "", request.form.get("code", ""))
        conn = get_db()
        ligne = conn.execute("SELECT * FROM email_codes WHERE user_id = ?", (g.user["id"],)).fetchone()
        if ligne is None or ligne["expires_at"] < time.time() or ligne["attempts"] >= ESSAIS_CODE:
            flash("Code expiré ou trop d’essais. Demandez un nouveau code.")
        else:
            conn.execute("UPDATE email_codes SET attempts = attempts + 1 WHERE user_id = ?", (g.user["id"],))
            conn.commit()
            if hmac.compare_digest(_hash_code(code), ligne["code_hash"]):
                conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (g.user["id"],))
                conn.execute("DELETE FROM email_codes WHERE user_id = ?", (g.user["id"],))
                conn.commit()
                flash("Votre adresse e-mail est validée. Bienvenue sur MidSport !")
                return redirect(url_for("views.accueil"))
            flash("Code incorrect.")
    return render_template("verify.html")


@bp.post("/verification/renvoyer")
@session_required
def verify_resend():
    if g.user["email_verified"]:
        return redirect(url_for("views.accueil"))
    ligne = get_db().execute("SELECT last_sent FROM email_codes WHERE user_id = ?", (g.user["id"],)).fetchone()
    reste = ATTENTE_RENVOI - (time.time() - ligne["last_sent"]) if ligne else 0
    if reste > 0:
        flash(f"Patientez {int(reste) + 1} secondes avant de demander un nouveau code.")
    elif _trop_de_demandes(ip_client(), 30):
        flash("Trop de demandes. Réessayez plus tard.")
    elif _envoyer_code(g.user["id"], g.user["identifier"]):
        flash("Un nouveau code vient d’être envoyé.")
    else:
        flash("L’e-mail n’a pas pu être envoyé. Réessayez dans un moment.")
    return redirect(url_for("auth.verify"))


# ---- mot de passe oublié --------------------------------------------------------------
def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="reset-mdp")


@bp.route("/mot-de-passe-oublie", methods=("GET", "POST"))
def forgot():
    if request.method == "POST":
        ip = ip_client()
        limite = 30 if ip in ("127.0.0.1", "::1") else 5    # IP non identifiée : limite globale plus large
        if _trop_de_demandes(ip, limite):
            flash("Trop de demandes. Réessayez dans quelques minutes.")
            return render_template("forgot.html")
        ident = normalise(request.form.get("identifier"))
        if ident:
            user = get_db().execute("SELECT * FROM users WHERE identifier = ?", (ident,)).fetchone()
            if user:
                token = _serializer().dumps({"id": user["id"], "h": user["password_hash"][-12:]})
                chemin = url_for("auth.reset", token=token)
                base = os.environ.get("PUBLIC_URL", "").rstrip("/")
                lien = base + chemin if base else url_for("auth.reset", token=token, _external=True)
                try:
                    envoyer_mail(ident, "MidSport : réinitialisation de votre mot de passe",
                                 "Pour choisir un nouveau mot de passe, ouvrez ce lien (valable 1 heure) :\n\n"
                                 f"{lien}\n\nSi vous n’êtes pas à l’origine de cette demande, ignorez ce message.")
                except Exception:
                    current_app.logger.exception("Échec de l’envoi du lien de réinitialisation")
        # même réponse que le compte existe ou non
        flash("Si un compte correspond à cette adresse, un lien de réinitialisation vient d’être envoyé.")
        return redirect(url_for("auth.login"))
    return render_template("forgot.html")


@bp.route("/reinitialisation/<token>", methods=("GET", "POST"))
def reset(token):
    try:
        data = _serializer().loads(token, max_age=DUREE_LIEN)
    except (SignatureExpired, BadSignature):
        flash("Ce lien est invalide ou a expiré. Faites une nouvelle demande.")
        return redirect(url_for("auth.forgot"))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (data.get("id"),)).fetchone()
    # le lien ne sert qu'une fois : il est lié à l'ancien mot de passe
    if user is None or user["password_hash"][-12:] != data.get("h"):
        flash("Ce lien est invalide ou a expiré. Faites une nouvelle demande.")
        return redirect(url_for("auth.forgot"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if len(pw) < 8:
            flash("Le mot de passe doit contenir au moins 8 caractères.")
        else:
            # recevoir ce lien prouve aussi que l'adresse e-mail est la bonne
            conn.execute("UPDATE users SET password_hash = ?, email_verified = 1 WHERE id = ?",
                         (generate_password_hash(pw), user["id"]))
            conn.commit()
            session.clear()
            flash("Mot de passe modifié. Connectez-vous avec le nouveau.")
            return redirect(url_for("auth.login"))
    return render_template("reset.html")
