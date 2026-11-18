import os
import sqlite3
import uuid
from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template,
                   jsonify, request, send_from_directory, url_for)
from auth import SPORTS, login_required
from core import SQL_BLOQUES, bloque, enregistrer_image, supprimer_audio, supprimer_image
from texte import motif_like
from db import get_db

bp = Blueprint("views", __name__)
POSTEURS_MARKET = ("club", "agent", "coach")     # les joueurs ne postent pas sur le Market
PRIX = {"club": 1700, "joueur": 750, "agent": 750, "coach": 750}   # Fr / mois (pour le futur paiement)
EXT_AUDIO = {"audio/webm": "webm", "audio/ogg": "ogg", "audio/mp4": "m4a",
             "audio/mpeg": "mp3", "audio/wav": "wav"}


# ---- règles d'accès du cahier des charges -------------------------------------------
def peut_voir_role(role):
    """Un club voit tous les profils ; un particulier ne voit que les clubs."""
    return g.user["role"] == "club" or role == "club"


def peut_ecrire(cible):
    """Un club écrit à tout le monde ; un particulier écrit aux clubs."""
    return g.user["id"] != cible["id"] and (g.user["role"] == "club" or cible["role"] == "club")


def compter_non_lus():
    return get_db().execute("SELECT COUNT(*) FROM messages WHERE recipient_id = :me AND read = 0 "
                            "AND sender_id NOT IN " + SQL_BLOQUES, {"me": g.user["id"]}).fetchone()[0]


@bp.app_context_processor
def contexte():
    if g.get("user") is None:
        return {}
    n = get_db().execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND read=0",
                         (g.user["id"],)).fetchone()[0]
    return {"nb_notifs": n, "nb_non_lus": compter_non_lus(), "peut_voir": peut_voir_role}


def utilisateur_ou_404(uid):
    u = get_db().execute("SELECT * FROM users WHERE id = ? AND suspended = 0", (uid,)).fetchone()
    if u is None:
        abort(404)
    return u


def notifier(user_id, texte, lien=None):
    get_db().execute("INSERT INTO notifications(user_id,text,link) VALUES (?,?,?)",
                     (user_id, texte, lien))


# ---- 1. Accueil ----------------------------------------------------------------------
@bp.get("/")
@login_required
def accueil():
    posts = get_db().execute("""
        SELECT p.id, p.body, p.image, p.created_at, u.id AS uid, u.name, u.photo, u.sport, u.role,
               (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS nb_likes,
               (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS nb_comments,
               EXISTS(SELECT 1 FROM likes WHERE post_id = p.id AND user_id = :me) AS liked,
               EXISTS(SELECT 1 FROM follows WHERE follower_id = :me AND followed_id = u.id) AS suivi
        FROM posts p JOIN users u ON u.id = p.user_id
        WHERE u.suspended = 0 AND u.id NOT IN """ + SQL_BLOQUES + """
        ORDER BY p.id DESC LIMIT 50""", {"me": g.user["id"]}).fetchall()
    return render_template("accueil.html", posts=posts)


@bp.post("/aimer/<int:post_id>")
@login_required
def aimer(post_id):
    conn = get_db()
    post = conn.execute("SELECT user_id FROM posts WHERE id=?", (post_id,)).fetchone()
    if post is None:
        abort(404)
    cur = conn.execute("DELETE FROM likes WHERE user_id=? AND post_id=?", (g.user["id"], post_id))
    if cur.rowcount == 0:
        conn.execute("INSERT INTO likes(user_id, post_id) VALUES (?,?)", (g.user["id"], post_id))
        if post["user_id"] != g.user["id"]:
            notifier(post["user_id"], f"{g.user['name']} a aimé votre publication.")
    conn.commit()
    return redirect(url_for("views.accueil"))


@bp.post("/suivre/<int:uid>")
@login_required
def suivre(uid):
    cible = utilisateur_ou_404(uid)
    if cible["id"] == g.user["id"] or not peut_voir_role(cible["role"]) or bloque(g.user["id"], uid):
        abort(403)
    conn = get_db()
    cur = conn.execute("DELETE FROM follows WHERE follower_id=? AND followed_id=?", (g.user["id"], uid))
    if cur.rowcount == 0:
        conn.execute("INSERT INTO follows VALUES (?,?)", (g.user["id"], uid))
        notifier(uid, f"{g.user['name']} vous suit à présent.", url_for("views.profil", uid=g.user["id"]))
    conn.commit()
    return redirect(request.form.get("retour") if (request.form.get("retour") or "").startswith("/")
                    and not (request.form.get("retour") or "").startswith("//") else url_for("views.accueil"))


# ---- 2. Notifications ----------------------------------------------------------------
@bp.get("/notifications")
@login_required
def notifications():
    conn = get_db()
    items = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50",
                         (g.user["id"],)).fetchall()
    conn.execute("UPDATE notifications SET read=1 WHERE user_id=?", (g.user["id"],))
    conn.commit()
    return render_template("notifications.html", items=items)


# ---- 3. Créer ------------------------------------------------------------------------
@bp.route("/creer", methods=("GET", "POST"))
@login_required
def creer():
    if request.method == "POST":
        texte = request.form.get("body", "").strip()
        fichier = request.files.get("image")
        image = enregistrer_image(fichier) if fichier and fichier.filename else None
        if fichier and fichier.filename and image is None:
            flash("Image non valide (JPEG, PNG ou WebP).")
        elif len(texte) > 2000 or not (texte or image):
            flash("Écrivez un texte (2000 caractères maximum) ou ajoutez une photo.")
            supprimer_image(image)
        else:
            conn = get_db()
            conn.execute("INSERT INTO posts(user_id, body, image) VALUES (?,?,?)", (g.user["id"], texte, image))
            conn.commit()
            return redirect(url_for("views.accueil"))
    return render_template("creer.html")


# ---- 4. Messagerie (texte + messages vocaux illimités) --------------------------------
@bp.get("/messages")
@login_required
def messages():
    convs = get_db().execute("""
        SELECT u.id, u.name, u.role, m.body, m.audio, m.created_at,
               (SELECT COUNT(*) FROM messages x WHERE x.sender_id = u.id AND x.recipient_id = :me AND x.read = 0) AS non_lus
        FROM messages m
        JOIN users u ON u.id = CASE WHEN m.sender_id = :me THEN m.recipient_id ELSE m.sender_id END
        WHERE m.id IN (SELECT MAX(id) FROM messages WHERE sender_id = :me OR recipient_id = :me
                       GROUP BY CASE WHEN sender_id = :me THEN recipient_id ELSE sender_id END)
        ORDER BY m.id DESC""", {"me": g.user["id"]}).fetchall()
    return render_template("messages.html", convs=convs)


@bp.route("/messages/<int:uid>", methods=("GET", "POST"))
@login_required
def conversation(uid):
    autre = utilisateur_ou_404(uid)
    if bloque(g.user["id"], uid):
        abort(403)
    conn = get_db()
    deja = conn.execute("SELECT 1 FROM messages WHERE (sender_id=:a AND recipient_id=:b) "
                        "OR (sender_id=:b AND recipient_id=:a) LIMIT 1",
                        {"a": g.user["id"], "b": uid}).fetchone()
    if not deja and not peut_ecrire(autre):
        abort(403)
    if request.method == "POST":
        texte = request.form.get("body", "").strip()
        if texte and len(texte) <= 2000 and (deja or peut_ecrire(autre)):
            conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES (?,?,?)",
                         (g.user["id"], uid, texte))
            notifier(uid, f"Nouveau message de {g.user['name']}.", url_for("views.conversation", uid=g.user["id"]))
            conn.commit()
        return redirect(url_for("views.conversation", uid=uid))
    conn.execute("UPDATE messages SET read = 1 WHERE recipient_id = ? AND sender_id = ? AND read = 0",
                 (g.user["id"], uid))                      # ouvrir la conversation = lire les messages reçus
    conn.commit()
    msgs = conn.execute("SELECT * FROM messages WHERE (sender_id=:a AND recipient_id=:b) "
                        "OR (sender_id=:b AND recipient_id=:a) ORDER BY id", {"a": g.user["id"], "b": uid}).fetchall()
    return render_template("conversation.html", autre=autre, msgs=msgs)


@bp.post("/messages/<int:uid>/vocal")
@login_required
def vocal(uid):
    autre = utilisateur_ou_404(uid)
    if bloque(g.user["id"], uid):
        abort(403)
    if not peut_ecrire(autre):
        abort(403)
    f = request.files.get("audio")
    mime = ((f.mimetype if f else "") or "").split(";")[0]
    if mime not in EXT_AUDIO:
        abort(400)
    nom = f"{uuid.uuid4().hex}.{EXT_AUDIO[mime]}"
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], nom))
    conn = get_db()
    conn.execute("INSERT INTO messages(sender_id,recipient_id,audio) VALUES (?,?,?)", (g.user["id"], uid, nom))
    notifier(uid, f"Message vocal de {g.user['name']}.", url_for("views.conversation", uid=g.user["id"]))
    conn.commit()
    return "", 204


@bp.get("/audio/<int:mid>")
@login_required
def audio(mid):
    m = get_db().execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if m is None or not m["audio"] or g.user["id"] not in (m["sender_id"], m["recipient_id"]):
        abort(404)
    return send_from_directory(current_app.config["UPLOAD_DIR"], m["audio"])


@bp.get("/messages/compteur")
@login_required
def messages_compteur():
    return jsonify(n=compter_non_lus())


@bp.get("/messages/<int:uid>/nouveaux")
@login_required
def messages_nouveaux(uid):
    """Messages arrivés depuis le dernier id connu (la page interroge cette adresse toutes les 4 secondes)."""
    utilisateur_ou_404(uid)
    if bloque(g.user["id"], uid):
        abort(403)
    try:
        apres = int(request.args.get("apres", "0"))
    except ValueError:
        apres = 0
    conn = get_db()
    msgs = conn.execute("SELECT * FROM messages WHERE id > :apres AND ((sender_id=:a AND recipient_id=:b) "
                        "OR (sender_id=:b AND recipient_id=:a)) ORDER BY id",
                        {"apres": apres, "a": g.user["id"], "b": uid}).fetchall()
    if msgs:
        conn.execute("UPDATE messages SET read = 1 WHERE recipient_id = ? AND sender_id = ? AND read = 0",
                     (g.user["id"], uid))
        conn.commit()
    return jsonify(dernier=msgs[-1]["id"] if msgs else apres, html=render_template("_bulles.html", msgs=msgs))


@bp.post("/messages/<int:mid>/supprimer")
@login_required
def message_supprimer(mid):
    conn = get_db()
    m = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if m is None:
        abort(404)
    if m["sender_id"] != g.user["id"]:
        abort(403)
    conn.execute("DELETE FROM messages WHERE id=?", (mid,))
    conn.commit()
    supprimer_audio(m["audio"])
    flash("Message supprimé.")
    return redirect(url_for("views.conversation", uid=m["recipient_id"]))


# ---- 5. Market ------------------------------------------------------------------------
POSTES = ("Gardien", "Défenseur", "Milieu", "Attaquant", "Arrière", "Ailier", "Ailier fort",
          "Meneur", "Pivot", "Demi-centre")


def _age(valeur):
    """Âge valide (0 à 100) ou None : une valeur invalide est simplement ignorée."""
    try:
        n = int(valeur)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= 100 else None


@bp.get("/market")
@login_required
def market():
    """Liste des joueurs, avec filtres facultatifs : sport, poste, âge minimum et maximum, disponibles seulement."""
    sport = request.args.get("sport", "")
    sport = sport if sport in SPORTS else ""
    poste = request.args.get("poste", "").strip()[:40]
    age_min, age_max = _age(request.args.get("age_min")), _age(request.args.get("age_max"))
    dispo = request.args.get("dispo") == "1"
    conditions, params = [], {}
    if sport:
        conditions.append("COALESCE(l.sport, u.sport) = :sport")
        params["sport"] = sport
    if poste:
        conditions.append("norm(l.position) LIKE :poste ESCAPE '\\'")
        params["poste"] = motif_like(poste)
    if age_min is not None:
        conditions.append("l.age >= :age_min")
        params["age_min"] = age_min
    if age_max is not None:
        conditions.append("l.age <= :age_max")
        params["age_max"] = age_max
    if dispo:
        conditions.append("l.sold = 0")
    conn = get_db()
    listings = conn.execute(
        "SELECT l.id, l.seller_id, l.player_name, l.position, l.age, l.price, l.sold, "
        "COALESCE(l.sport, u.sport) AS sport, u.name AS seller_name "
        "FROM listings l JOIN users u ON u.id = l.seller_id "
        + ("WHERE " + " AND ".join(conditions) + " " if conditions else "")
        + "ORDER BY l.sold, l.id DESC LIMIT 100", params).fetchall()
    nb = conn.execute("SELECT COUNT(*) FROM cart WHERE user_id=?", (g.user["id"],)).fetchone()[0]
    f = {"sport": sport, "poste": poste, "age_min": age_min, "age_max": age_max, "dispo": dispo}
    return render_template("market.html", listings=listings, nb_panier=nb, f=f, actifs=bool(conditions),
                           postes=POSTES, peut_poster=g.user["role"] in POSTEURS_MARKET)


@bp.post("/market/publier")
@login_required
def market_publier():
    if g.user["role"] not in POSTEURS_MARKET:
        abort(403)
    nom = request.form.get("player_name", "").strip()
    poste = request.form.get("position", "").strip()
    sport = request.form.get("sport") or g.user["sport"]
    try:
        age = int(request.form.get("age", ""))
        prix = int(request.form["price"]) if request.form.get("price") else None
    except ValueError:
        age, prix = 0, None
    if not nom or not poste or len(nom) > 80 or len(poste) > 40 or not 14 <= age <= 50 or (prix is not None and prix < 0) \
            or sport not in SPORTS:
        flash("Vérifiez le nom, le poste, le sport, l’âge (14 à 50 ans) et le prix.")
    else:
        conn = get_db()
        conn.execute("INSERT INTO listings(seller_id,player_name,position,age,price,sport) VALUES (?,?,?,?,?,?)",
                     (g.user["id"], nom, poste, age, prix, sport))
        conn.commit()
        flash("Joueur mis sur le marché.")
    return redirect(url_for("views.market"))


@bp.post("/market/panier/<int:lid>")
@login_required
def panier_ajouter(lid):
    conn = get_db()
    l = conn.execute("SELECT * FROM listings WHERE id=?", (lid,)).fetchone()
    if l is None:
        abort(404)
    if g.user["role"] != "club" or l["seller_id"] == g.user["id"]:
        abort(403)
    if l["sold"]:
        flash("Ce joueur n’est plus disponible.")
        return redirect(url_for("views.market"))
    conn.execute("INSERT OR IGNORE INTO cart VALUES (?,?)", (g.user["id"], lid))
    conn.commit()
    flash("Ajouté au panier.")
    return redirect(url_for("views.market"))


@bp.get("/panier")
@login_required
def panier():
    items = get_db().execute("""
        SELECT l.*, u.name AS seller_name FROM cart c JOIN listings l ON l.id = c.listing_id
        JOIN users u ON u.id = l.seller_id WHERE c.user_id=?""", (g.user["id"],)).fetchall()
    return render_template("panier.html", items=items)


@bp.post("/panier/<int:lid>/retirer")
@login_required
def panier_retirer(lid):
    conn = get_db()
    conn.execute("DELETE FROM cart WHERE user_id=? AND listing_id=?", (g.user["id"], lid))
    conn.commit()
    return redirect(url_for("views.panier"))


def _mon_annonce(lid):
    l = get_db().execute("SELECT * FROM listings WHERE id=?", (lid,)).fetchone()
    if l is None:
        abort(404)
    if l["seller_id"] != g.user["id"]:
        abort(403)
    return l


@bp.post("/market/<int:lid>/vendu")
@login_required
def market_vendu(lid):
    l = _mon_annonce(lid)
    conn = get_db()
    conn.execute("UPDATE listings SET sold = ? WHERE id = ?", (0 if l["sold"] else 1, lid))
    conn.commit()
    flash("Annonce remise en vente." if l["sold"] else "Annonce marquée comme vendue.")
    return redirect(url_for("views.market"))


@bp.post("/market/<int:lid>/supprimer")
@login_required
def market_supprimer(lid):
    _mon_annonce(lid)
    conn = get_db()
    conn.execute("DELETE FROM listings WHERE id = ?", (lid,))
    conn.commit()
    flash("Annonce retirée.")
    return redirect(url_for("views.market"))


# ---- 6. Profil et abonnement ----------------------------------------------------------
@bp.get("/profil")
@bp.get("/profil/<int:uid>")
@login_required
def profil(uid=None):
    conn = get_db()
    u = g.user if uid in (None, g.user["id"]) else utilisateur_ou_404(uid)
    moi = u["id"] == g.user["id"]
    if not moi:
        if not peut_voir_role(u["role"]):
            abort(403)
        if bloque(g.user["id"], u["id"]):
            abort(404)
        texte = f"{g.user['name']} a visité votre profil."
        deja = conn.execute("SELECT 1 FROM notifications WHERE user_id=? AND text=? AND read=0",
                            (u["id"], texte)).fetchone()
        if not deja:
            notifier(u["id"], texte, url_for("views.profil", uid=g.user["id"]))
            conn.commit()
    stats = {
        "abonnes": conn.execute("SELECT COUNT(*) FROM follows WHERE followed_id=?", (u["id"],)).fetchone()[0],
        "abonnements": conn.execute("SELECT COUNT(*) FROM follows WHERE follower_id=?", (u["id"],)).fetchone()[0],
        "suivi": bool(conn.execute("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?",
                                   (g.user["id"], u["id"])).fetchone()),
    }
    posts = conn.execute("SELECT * FROM posts WHERE user_id=? ORDER BY id DESC LIMIT 30", (u["id"],)).fetchall()
    premium = bool(conn.execute("SELECT 1 FROM users WHERE id=? AND premium_until > datetime('now')",
                                (u["id"],)).fetchone())
    return render_template("profil.html", u=u, moi=moi, stats=stats, posts=posts, premium=premium,
                           ecrire=(not moi and peut_ecrire(u)))


@bp.get("/abonnement")
@login_required
def abonnement():
    # Lancement : le premium « arrive bientôt ». Le paiement (Wave / Moov / MTN) sera ajouté ensuite ;
    # la table `payments` et la constante PRIX sont déjà prêtes pour cela.
    return render_template("abonnement.html")
