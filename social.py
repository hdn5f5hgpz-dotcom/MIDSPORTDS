"""Recherche, profil, photos, commentaires, blocage, signalement, administration, pages légales."""
import os
from flask import (Blueprint, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from auth import _ouvrir_session, login_required
from core import (NOM_IMAGE, SQL_BLOQUES, bloque, dossier_images, enregistrer_image,
                  supprimer_audio, supprimer_image)
from db import get_db
from views import notifier, peut_voir_role, utilisateur_ou_404

bp = Blueprint("social", __name__)
RAISONS = ("Contenu inapproprié", "Harcèlement ou menaces", "Faux profil ou usurpation", "Arnaque", "Autre")


def admin_required(view):
    @login_required
    def wrapped(*args, **kwargs):
        if not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# ---- recherche ------------------------------------------------------------------------
@bp.get("/recherche")
@login_required
def recherche():
    q = request.args.get("q", "").strip()[:60]
    resultats = []
    if q:
        motif = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        resultats = get_db().execute(
            "SELECT id, name, role, sport, city, photo FROM users "
            "WHERE name LIKE :p ESCAPE '\\' AND suspended = 0 AND email_verified = 1 AND id != :me "
            "AND (role = 'club' OR :club = 1) AND id NOT IN " + SQL_BLOQUES + " ORDER BY name LIMIT 30",
            {"p": motif, "me": g.user["id"], "club": int(g.user["role"] == "club")}).fetchall()
    return render_template("recherche.html", q=q, resultats=resultats)


# ---- modifier son profil --------------------------------------------------------------
@bp.route("/profil/modifier", methods=("GET", "POST"))
@login_required
def modifier_profil():
    conn = get_db()
    if request.method == "POST":
        nom = request.form.get("name", "").strip()
        bio = request.form.get("bio", "").strip()
        ville = request.form.get("city", "").strip()
        poste = request.form.get("position", "").strip()
        fichier = request.files.get("photo")
        photo = enregistrer_image(fichier, 600) if fichier and fichier.filename else None
        if not nom or len(nom) > 80 or len(bio) > 300 or len(ville) > 60 or len(poste) > 40:
            flash("Vérifiez les champs : nom (80), description (300), ville (60), poste (40 caractères maximum).")
        elif fichier and fichier.filename and photo is None:
            flash("Image non valide (JPEG, PNG ou WebP).")
        else:
            conn.execute("UPDATE users SET name=?, bio=?, city=?, position=? WHERE id=?",
                         (nom, bio or None, ville or None, poste or None, g.user["id"]))
            if photo:
                supprimer_image(g.user["photo"])
                conn.execute("UPDATE users SET photo=? WHERE id=?", (photo, g.user["id"]))
            conn.commit()
            flash("Profil mis à jour.")
            return redirect(url_for("views.profil"))
        supprimer_image(photo)
    bloques = conn.execute("SELECT u.id, u.name FROM blocks b JOIN users u ON u.id = b.blocked_id "
                           "WHERE b.blocker_id = ? ORDER BY u.name", (g.user["id"],)).fetchall()
    return render_template("modifier_profil.html", bloques=bloques)


@bp.post("/profil/mot-de-passe")
@login_required
def changer_mot_de_passe():
    nouveau = request.form.get("nouveau", "")
    if not check_password_hash(g.user["password_hash"], request.form.get("actuel", "")):
        flash("Mot de passe actuel incorrect.")
    elif len(nouveau) < 8:
        flash("Le nouveau mot de passe doit contenir au moins 8 caractères.")
    else:
        conn = get_db()
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(nouveau), g.user["id"]))
        conn.commit()
        _ouvrir_session(g.user["id"])          # les autres appareils sont déconnectés
        flash("Mot de passe modifié.")
    return redirect(url_for("social.modifier_profil"))


@bp.post("/profil/supprimer")
@login_required
def supprimer_compte():
    if not check_password_hash(g.user["password_hash"], request.form.get("actuel", "")):
        flash("Mot de passe incorrect : le compte n’a pas été supprimé.")
        return redirect(url_for("social.modifier_profil"))
    conn = get_db()
    me = g.user["id"]
    images = [r[0] for r in conn.execute("SELECT image FROM posts WHERE user_id=? AND image IS NOT NULL", (me,))]
    audios = [r[0] for r in conn.execute("SELECT audio FROM messages WHERE (sender_id=? OR recipient_id=?) "
                                         "AND audio IS NOT NULL", (me, me))]
    photo = g.user["photo"]
    conn.execute("DELETE FROM reports WHERE (kind='user' AND target_id=?) OR author_id=?", (me, me))
    conn.execute("DELETE FROM users WHERE id=?", (me,))      # supprime aussi publications, messages, etc.
    conn.commit()
    for nom in images + [photo]:
        supprimer_image(nom)
    for nom in audios:
        supprimer_audio(nom)
    session.clear()
    flash("Votre compte et vos données ont été supprimés.")
    return redirect(url_for("auth.login"))


@bp.get("/img/<nom>")
@login_required
def image(nom):
    if not NOM_IMAGE.match(nom):
        abort(404)
    rep = send_from_directory(dossier_images(), nom, max_age=86400)
    rep.cache_control.private = True
    return rep


# ---- publications : page, commentaires, suppression -----------------------------------
def _publication(pid):
    p = get_db().execute(
        "SELECT p.*, u.name, u.photo, u.role, u.sport, u.id AS uid FROM posts p JOIN users u ON u.id = p.user_id "
        "WHERE p.id = ? AND u.suspended = 0", (pid,)).fetchone()
    if p is None or (p["uid"] != g.user["id"] and bloque(g.user["id"], p["uid"])):
        abort(404)
    return p


@bp.get("/publication/<int:pid>")
@login_required
def publication(pid):
    p = _publication(pid)
    commentaires = get_db().execute(
        "SELECT c.id, c.body, c.created_at, u.id AS uid, u.name, u.photo, u.role FROM comments c "
        "JOIN users u ON u.id = c.user_id WHERE c.post_id = :pid AND u.suspended = 0 AND u.id NOT IN "
        + SQL_BLOQUES + " ORDER BY c.id LIMIT 200", {"pid": pid, "me": g.user["id"]}).fetchall()
    return render_template("publication.html", p=p, commentaires=commentaires)


@bp.post("/publication/<int:pid>/commenter")
@login_required
def commenter(pid):
    p = _publication(pid)
    texte = request.form.get("body", "").strip()
    if not texte or len(texte) > 500:
        flash("Écrivez un commentaire de 500 caractères maximum.")
    else:
        conn = get_db()
        conn.execute("INSERT INTO comments(post_id, user_id, body) VALUES (?,?,?)", (pid, g.user["id"], texte))
        if p["uid"] != g.user["id"]:
            notifier(p["uid"], f"{g.user['name']} a commenté votre publication.",
                     url_for("social.publication", pid=pid))
        conn.commit()
    return redirect(url_for("social.publication", pid=pid))


@bp.post("/publication/<int:pid>/supprimer")
@login_required
def supprimer_publication(pid):
    p = _publication(pid)
    if p["uid"] != g.user["id"]:
        abort(403)
    conn = get_db()
    conn.execute("DELETE FROM posts WHERE id=?", (pid,))
    conn.commit()
    supprimer_image(p["image"])
    flash("Publication supprimée.")
    return redirect(url_for("views.accueil"))


# ---- blocage et signalement -----------------------------------------------------------
@bp.post("/bloquer/<int:uid>")
@login_required
def bloquer(uid):
    utilisateur_ou_404(uid)
    me = g.user["id"]
    if uid == me:
        abort(400)
    conn = get_db()
    cur = conn.execute("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?", (me, uid))
    if cur.rowcount == 0:
        conn.execute("INSERT INTO blocks VALUES (?,?)", (me, uid))
        conn.execute("DELETE FROM follows WHERE (follower_id=? AND followed_id=?) OR (follower_id=? AND followed_id=?)",
                     (me, uid, uid, me))
        flash("Compte bloqué. Cette personne ne peut plus vous écrire ni voir vos publications.")
        dest = url_for("views.accueil")
    else:
        flash("Compte débloqué.")
        dest = url_for("social.modifier_profil")
    conn.commit()
    return redirect(dest)


@bp.post("/signaler")
@login_required
def signaler():
    kind = request.form.get("kind")
    raison = request.form.get("reason")
    try:
        cible = int(request.form.get("target_id", ""))
    except ValueError:
        abort(400)
    table = {"post": "posts", "comment": "comments", "user": "users", "listing": "listings",
             "message": "messages"}.get(kind)
    if table is None or raison not in RAISONS:
        abort(400)
    conn = get_db()
    if conn.execute(f"SELECT 1 FROM {table} WHERE id=?", (cible,)).fetchone() is None or \
            (kind == "user" and cible == g.user["id"]):
        abort(404)
    if kind == "listing" and conn.execute("SELECT 1 FROM listings WHERE id=? AND seller_id=?", (cible, g.user["id"])).fetchone():
        abort(400)
    detail = auteur = None
    if kind == "message":      # seul le destinataire signale ; on garde une copie au cas où l'auteur le supprime
        m = conn.execute("SELECT * FROM messages WHERE id=? AND recipient_id=?", (cible, g.user["id"])).fetchone()
        if m is None:
            abort(404)
        detail, auteur = (m["body"] or "Message vocal")[:200], m["sender_id"]
    deja = conn.execute("SELECT 1 FROM reports WHERE reporter_id=? AND kind=? AND target_id=? AND status='ouvert'",
                        (g.user["id"], kind, cible)).fetchone()
    if not deja:
        conn.execute("INSERT INTO reports(reporter_id, kind, target_id, reason, detail, author_id) VALUES (?,?,?,?,?,?)",
                     (g.user["id"], kind, cible, raison, detail, auteur))
        conn.commit()
    flash("Merci, votre signalement a été transmis à l’équipe.")
    retour = request.form.get("retour", "")
    return redirect(retour if retour.startswith("/") and not retour.startswith("//") else url_for("views.accueil"))


# ---- administration -------------------------------------------------------------------
def _resume(conn, r):
    """Décrit la cible d'un signalement : texte, auteur."""
    info = {"id": r["id"], "kind": r["kind"], "reason": r["reason"], "reporter": r["reporter"],
            "created_at": r["created_at"], "texte": "(contenu déjà supprimé)", "auteur": None}
    if r["kind"] == "post":
        c = conn.execute("SELECT p.body, p.image, u.id AS uid, u.name FROM posts p JOIN users u ON u.id=p.user_id "
                         "WHERE p.id=?", (r["target_id"],)).fetchone()
    elif r["kind"] == "comment":
        c = conn.execute("SELECT c.body, NULL AS image, u.id AS uid, u.name FROM comments c "
                         "JOIN users u ON u.id=c.user_id WHERE c.id=?", (r["target_id"],)).fetchone()
    elif r["kind"] == "message":
        c = conn.execute("SELECT COALESCE(NULLIF(m.body, ''), 'Message vocal') AS body, NULL AS image, "
                         "u.id AS uid, u.name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?",
                         (r["target_id"],)).fetchone()
        if c is None and r["author_id"]:        # message supprimé depuis : on utilise la copie
            u = conn.execute("SELECT id, name FROM users WHERE id=?", (r["author_id"],)).fetchone()
            if u:
                info.update(texte=(r["detail"] or "")[:200] + " (message supprimé depuis)", auteur=u["id"],
                            auteur_nom=u["name"], image=None)
                return info
    elif r["kind"] == "listing":
        c = conn.execute("SELECT l.player_name || ' (' || l.position || ', ' || l.age || ' ans)' AS body, NULL AS image, "
                         "u.id AS uid, u.name FROM listings l JOIN users u ON u.id=l.seller_id WHERE l.id=?",
                         (r["target_id"],)).fetchone()
    else:
        c = conn.execute("SELECT 'Profil signalé' AS body, NULL AS image, id AS uid, name FROM users WHERE id=?",
                         (r["target_id"],)).fetchone()
    if c:
        info["texte"] = (c["body"] or "(photo seule)")[:200]
        info["auteur"], info["auteur_nom"], info["image"] = c["uid"], c["name"], c["image"]
    return info


@bp.get("/admin")
@admin_required
def admin():
    conn = get_db()
    lignes = conn.execute("SELECT r.*, u.name AS reporter FROM reports r JOIN users u ON u.id=r.reporter_id "
                          "WHERE r.status='ouvert' ORDER BY r.id").fetchall()
    suspendus = conn.execute("SELECT id, name, identifier FROM users WHERE suspended=1").fetchall()
    return render_template("admin.html", signalements=[_resume(conn, r) for r in lignes], suspendus=suspendus)


@bp.post("/admin/signalement/<int:rid>/<action>")
@admin_required
def admin_action(rid, action):
    if action not in ("classer", "supprimer", "suspendre"):
        abort(404)
    conn = get_db()
    r = conn.execute("SELECT r.*, '' AS reporter FROM reports r WHERE id=?", (rid,)).fetchone()
    if r is None:
        abort(404)
    info = _resume(conn, r)
    if action == "supprimer" and info["auteur"]:
        if r["kind"] == "post":
            conn.execute("DELETE FROM posts WHERE id=?", (r["target_id"],))
            supprimer_image(info.get("image"))
        elif r["kind"] == "comment":
            conn.execute("DELETE FROM comments WHERE id=?", (r["target_id"],))
        elif r["kind"] == "listing":
            conn.execute("DELETE FROM listings WHERE id=?", (r["target_id"],))
        elif r["kind"] == "message":
            m = conn.execute("SELECT audio FROM messages WHERE id=?", (r["target_id"],)).fetchone()
            conn.execute("DELETE FROM messages WHERE id=?", (r["target_id"],))
            if m:
                supprimer_audio(m["audio"])
    if action == "suspendre" and info["auteur"] and info["auteur"] != g.user["id"]:
        conn.execute("UPDATE users SET suspended=1 WHERE id=? AND is_admin=0", (info["auteur"],))
    conn.execute("UPDATE reports SET status='traité' WHERE kind=? AND target_id=? AND status='ouvert'",
                 (r["kind"], r["target_id"]))
    conn.commit()
    flash("Signalement traité.")
    return redirect(url_for("social.admin"))


@bp.post("/admin/utilisateur/<int:uid>/retablir")
@admin_required
def admin_retablir(uid):
    conn = get_db()
    conn.execute("UPDATE users SET suspended=0 WHERE id=?", (uid,))
    conn.commit()
    flash("Compte rétabli.")
    return redirect(url_for("social.admin"))


# ---- pages légales (publiques) --------------------------------------------------------
def _contact():
    return os.environ.get("CONTACT_EMAIL", "l’adresse de contact indiquée par l’administrateur du site")


@bp.get("/conditions")
def conditions():
    return render_template("conditions.html", contact=_contact())


@bp.get("/confidentialite")
def confidentialite():
    return render_template("confidentialite.html", contact=_contact())
