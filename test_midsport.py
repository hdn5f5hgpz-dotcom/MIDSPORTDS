import io, json, os, re, sqlite3, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import auth, db
from app import app
from PIL import Image

app.config["TESTING"] = True
MAILS = []
auth.envoyer_mail = lambda dest, sujet, corps: MAILS.append((dest, sujet, corps))   # capture au lieu d'envoyer
ok = lambda cond, msg: print(("OK   " if cond else "ECHEC"), msg) or (cond or sys.exit(1))
DB = lambda: sqlite3.connect(app.config["DATABASE"])
client = app.test_client

def csrf(c, url):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(url, follow_redirects=True).get_data(as_text=True)).group(1)

def post(c, url, data=None, page="/creer", follow=True):
    return c.post(url, data={**(data or {}), "csrf": csrf(c, page)}, follow_redirects=follow)

def texte(r): return r.get_data(as_text=True)
def code_recu(email):
    return re.search(r"\b(\d{6})\b", [m for m in MAILS if m[0] == email][-1][2]).group(1)

def inscrire(role, nom, email, sport="football"):
    c = client()
    post(c, "/inscription", dict(role=role, name=nom, sport=sport, identifier=email, password="motdepasse123", terms="1"), "/inscription")
    post(c, "/verification", dict(code=code_recu(email)), "/verification")
    return c

def png(couleur=(200, 30, 30), taille=(800, 600)):
    b = io.BytesIO(); Image.new("RGB", taille, couleur).save(b, "PNG"); b.seek(0); return b

# ---------- bases ----------
c = client(); r = c.get("/"); ok(r.status_code == 302 and "/connexion" in r.headers["Location"], "accueil protégé")
r = c.post("/connexion", data={"identifier": "a@b.co", "password": "x"}); ok(r.status_code == 400 and "Requête invalide" in texte(r), "CSRF obligatoire, page d’erreur en français")
ok(client().get("/page-inexistante").status_code == 404, "page 404")
for u in ("/conditions", "/confidentialite", "/connexion", "/inscription", "/mot-de-passe-oublie"):
    ok(client().get(u).status_code == 200, "page publique " + u)
ok("Pas de connexion Internet" in texte(inscrire("club", "FC Test", "club@test.com").get("/")), "bandeau hors connexion présent")

# ---------- inscription : e-mail seul, conditions, doublons ----------
def essai(**kw):
    d = dict(role="club", name="X", sport="football", identifier="x@test.com", password="motdepasse123", terms="1"); d.update(kw)
    return texte(post(client(), "/inscription", d, "/inscription"))
ok("adresse e-mail valide" in essai(identifier="+22501020304"), "numéro de téléphone refusé : e-mail obligatoire")
ok("conditions" in essai(terms=""), "conditions d’utilisation obligatoires")
ok("8 caractères" in essai(password="court"), "mot de passe court refusé")
ok("existe déjà" in essai(identifier="club@test.com"), "e-mail déjà pris refusé")
h = DB().execute("select password_hash from users where id=1").fetchone()[0]
ok(h.startswith(("scrypt:", "pbkdf2:")) and "motdepasse123" not in h, "mot de passe haché")

# ---------- validation de l'e-mail par code ----------
c = client()
r = post(c, "/inscription", dict(role="joueur", name="Joueur Un", sport="basketball", identifier="joueur@test.com", password="motdepasse123", terms="1"), "/inscription")
ok("Validez votre adresse e-mail" in texte(r), "après l’inscription : page de validation")
ok(MAILS[-1][0] == "joueur@test.com" and re.search(r"\b\d{6}\b", MAILS[-1][2]), "code à 6 chiffres envoyé par e-mail")
ok(c.get("/").status_code == 302 and "/verification" in c.get("/").headers["Location"], "pages protégées tant que l’e-mail n’est pas validé")
ok("incorrect" in texte(post(c, "/verification", dict(code="000000"), "/verification")), "mauvais code refusé")
ok("Patientez" in texte(post(c, "/verification/renvoyer", page="/verification")), "renvoi trop rapide refusé")
con = DB(); con.execute("update email_codes set last_sent = last_sent - 120"); con.commit()
n = len(MAILS); post(c, "/verification/renvoyer", page="/verification"); ok(len(MAILS) == n + 1, "nouveau code envoyé après l’attente")
ok("Bienvenue" in texte(post(c, "/verification", dict(code=code_recu("joueur@test.com")), "/verification")), "bon code : compte validé")
joueur = c; ok(joueur.get("/").status_code == 200, "accès à l’appli après validation")
c2 = client(); post(c2, "/inscription", dict(role="agent", name="Agent Un", sport="football", identifier="agent@test.com", password="motdepasse123", terms="1"), "/inscription")
bon = code_recu("agent@test.com")
for _ in range(5): post(c2, "/verification", dict(code="111111" if bon != "111111" else "222222"), "/verification")
ok("trop d’essais" in texte(post(c2, "/verification", dict(code=bon), "/verification")), "5 mauvais essais : code bloqué même s’il est bon")
con = DB(); con.execute("update email_codes set expires_at = 1"); con.commit()
ok("expiré" in texte(post(c2, "/verification", dict(code=bon), "/verification")), "code expiré refusé")
con = DB(); con.execute("update email_codes set last_sent = 1"); con.commit(); post(c2, "/verification/renvoyer", page="/verification")
post(c2, "/verification", dict(code=code_recu("agent@test.com")), "/verification"); agent = c2
ok(agent.get("/").status_code == 200, "nouveau code accepté")
club = client(); post(club, "/connexion", dict(identifier="club@test.com", password="motdepasse123"), "/connexion")
club2 = inscrire("club", "AS Deux", "club2@test.com")

# ---------- limite de tentatives de connexion ----------
auth._echecs.clear(); x = client()
for _ in range(5): r = post(x, "/connexion", dict(identifier="club@test.com", password="faux"), "/connexion")
ok("Trop de tentatives" in texte(post(x, "/connexion", dict(identifier="club@test.com", password="faux"), "/connexion")), "6e essai : pause de 15 minutes")
ok("Trop de tentatives" in texte(post(x, "/connexion", dict(identifier="club@test.com", password="motdepasse123"), "/connexion")), "même le bon mot de passe est refusé pendant la pause")
ok("Trop de tentatives" not in texte(post(x, "/connexion", dict(identifier="club2@test.com", password="faux"), "/connexion")), "un autre compte n’est pas bloqué")
auth._echecs.clear()
ok("incorrect" in texte(post(client(), "/connexion", dict(identifier="club@test.com", password="faux"), "/connexion")), "mauvais mot de passe refusé")
r = post(client(), "/connexion?next=//evil.com", dict(identifier="club@test.com", password="motdepasse123"), "/connexion", follow=False)
ok("evil.com" not in (r.headers.get("Location") or ""), "pas de redirection ouverte")

# ---------- publications, photos, commentaires ----------
ok("Écrivez" in texte(post(club, "/creer", dict(body="  "), "/creer")), "publication vide refusée")
r = post(club, "/creer", dict(body="Bonjour <b>MidSport</b>")); ok("Bonjour &lt;b&gt;" in texte(r), "publication créée et échappée (XSS)")
exif = Image.Exif(); exif[0x010F] = "AppareilSecret"; b = io.BytesIO(); Image.new("RGB", (1600, 1200), "green").save(b, "JPEG", exif=exif); b.seek(0)
r = post(club, "/creer", {"body": "Avec photo", "image": (b, "photo.jpg")}, "/creer"); t = texte(r)
nom = re.search(r"/img/([0-9a-f]{32}\.jpg)", t).group(1)
fichier = os.path.join(app.config["UPLOAD_DIR"], "images", nom); im = Image.open(fichier)
ok("Avec photo" in t and max(im.size) <= 1280 and not dict(im.getexif()), "photo publiée, réduite, métadonnées retirées")
ok(club.get("/img/" + nom).status_code == 200, "photo visible pour un membre connecté")
ok(client().get("/img/" + nom).status_code == 302, "photo invisible sans connexion")
ok(club.get("/img/../app.py").status_code == 404 and club.get("/img/x.jpg").status_code == 404, "noms de fichiers invalides refusés")
ok("non valide" in texte(post(club, "/creer", {"body": "x", "image": (io.BytesIO(b"pas une image"), "a.jpg")}, "/creer")), "faux fichier image refusé")
ok("Image non valide" in texte(post(club, "/creer", {"body": "x", "image": (io.BytesIO(b"<svg onload=alert(1)>"), "a.svg")}, "/creer")), "SVG refusé")
r = post(joueur, "/aimer/1", page="/creer"); ok("1 j’aime" in texte(r), "j’aime")
ok("Joueur Un a aimé" in texte(club.get("/notifications")), "notification de j’aime")
r = post(joueur, "/publication/1/commenter", dict(body="Bravo !"), "/publication/1"); ok("Bravo !" in texte(r), "commentaire ajouté")
ok("1 commentaire" in texte(joueur.get("/")), "compteur de commentaires dans le fil")
ok("Joueur Un a commenté" in texte(club.get("/notifications")), "notification de commentaire")
ok('class="share"' in texte(joueur.get("/")), "bouton Partager")
ok(joueur.post("/publication/1/supprimer", data={"csrf": csrf(joueur, "/creer")}).status_code == 403, "on ne supprime pas la publication d’un autre")

# ---------- règles de visite et de messagerie ----------
ok(club.get("/profil/2").status_code == 200, "club voit le profil d’un joueur")
ok(joueur.get("/profil/1").status_code == 200, "joueur voit le profil d’un club")
ok(joueur.get("/profil/3").status_code == 403, "joueur ne voit pas un autre particulier")
ok("Bonjour club" in texte(post(joueur, "/messages/1", dict(body="Bonjour club"), "/messages/1")), "joueur écrit à un club")
ok(joueur.get("/messages/3").status_code == 403, "joueur n’écrit pas à un agent")
ok("Réponse" in texte(post(club, "/messages/2", dict(body="Réponse du club"), "/messages/2")), "club écrit à un particulier")
c0 = csrf(club, "/messages/2")
r = club.post("/messages/2/vocal", data={"csrf": c0, "audio": (io.BytesIO(b"fakeaudio"), "v.webm", "audio/webm")}, content_type="multipart/form-data"); ok(r.status_code == 204, "message vocal envoyé")
r = club.post("/messages/2/vocal", data={"csrf": c0, "audio": (io.BytesIO(b"x"), "v.exe", "application/x-msdownload")}, content_type="multipart/form-data"); ok(r.status_code == 400, "fichier non audio refusé")
mid = DB().execute("select id from messages where audio is not null").fetchone()[0]
ok(joueur.get(f"/audio/{mid}").status_code == 200 and agent.get(f"/audio/{mid}").status_code == 404, "vocal : seuls les 2 correspondants l’écoutent")

# ---------- messagerie : non lus, direct, suppression ----------
ok(joueur.get("/messages/compteur").get_json()["n"] == 2, "compteur de messages non lus")
t = texte(joueur.get("/messages")); ok('class="dot"' in t and "font-weight:700" in t, "liste : pastille et conversation en gras")
ok('id="dot-msg"' in t, "pastille sur l’icône de messagerie")
ok("Réponse du club" in texte(joueur.get("/messages/1")) and joueur.get("/messages/compteur").get_json()["n"] == 0, "ouvrir la conversation marque les messages comme lus")
dernier = DB().execute("select max(id) from messages").fetchone()[0]
post(club, "/messages/2", dict(body="Salut en direct"), "/messages/2")
j = joueur.get(f"/messages/1/nouveaux?apres={dernier}").get_json()
ok("Salut en direct" in j["html"] and j["dernier"] == dernier + 1, "nouveau message reçu sans recharger la page")
ok(joueur.get("/messages/compteur").get_json()["n"] == 0, "message reçu en direct marqué lu")
ok(joueur.get(f"/messages/1/nouveaux?apres={j['dernier']}").get_json()["html"].strip() == "", "rien de nouveau : réponse vide")
ok("Salut en direct" not in agent.get("/messages/1/nouveaux?apres=0").get_json()["html"], "un tiers ne voit pas la conversation")
msg = DB().execute("select id from messages where body='Salut en direct'").fetchone()[0]
ok(joueur.post(f"/messages/{msg}/supprimer", data={"csrf": csrf(joueur, "/creer")}).status_code == 403, "on ne supprime pas le message d’un autre")
ok("Message supprimé" in texte(post(club, f"/messages/{msg}/supprimer", page="/creer")) and DB().execute("select count(*) from messages where id=?", (msg,)).fetchone()[0] == 0, "l’auteur supprime son message")
chemin = os.path.join(app.config["UPLOAD_DIR"], DB().execute("select audio from messages where id=?", (mid,)).fetchone()[0]); ok(os.path.exists(chemin), "fichier vocal présent")
post(club, f"/messages/{mid}/supprimer", page="/creer"); ok(not os.path.exists(chemin), "le fichier vocal est supprimé avec le message")
ok(club.post("/messages/99999/supprimer", data={"csrf": csrf(club, "/creer")}).status_code == 404, "message inexistant")

# ---------- Market ----------
r = post(club, "/market/publier", dict(player_name="Ismaël D.", position="Attaquant", age="22", price="5000000"), "/market"); ok("5 000 000 Fr" in texte(r), "club publie un joueur")
ok("Cheikh S." in texte(post(agent, "/market/publier", dict(player_name="Cheikh S.", position="Meneur", age="19"), "/market")), "agent publie un joueur")
ok(joueur.post("/market/publier", data={"csrf": csrf(joueur, "/creer"), "player_name": "X", "position": "Y", "age": "20"}).status_code == 403, "joueur ne poste pas sur le Market")
ok("Acheter" in texte(club2.get("/market")) and "Acheter" not in texte(joueur.get("/market")), "Acheter réservé aux clubs")
ok("Ajouté au panier" in texte(post(club2, "/market/panier/1", page="/creer")), "panier")
ok(agent.post("/market/panier/1", data={"csrf": csrf(agent, "/creer")}).status_code == 403, "agent ne peut pas acheter")
ok("arrive bientôt" in texte(joueur.get("/profil")) and joueur.post("/abonnement", data={"csrf": csrf(joueur, "/creer")}).status_code == 405, "premium : bientôt, aucun paiement")

# ---------- Market : vendu, retirer, signaler une annonce ----------
ok(club2.post("/market/1/vendu", data={"csrf": csrf(club2, "/creer")}).status_code == 403, "on ne marque pas vendue l’annonce d’un autre")
ok(club2.post("/market/1/supprimer", data={"csrf": csrf(club2, "/creer")}).status_code == 403, "on ne retire pas l’annonce d’un autre")
ok("marquée comme vendue" in texte(post(club, "/market/1/vendu", page="/creer")), "le vendeur marque son annonce vendue")
t = texte(club2.get("/market")); ok("Vendu" in t and t.index("Cheikh S.") < t.index("Ismaël D."), "annonce vendue : badge et placée en dernier")
ok("plus disponible" in texte(post(club2, "/market/panier/1", page="/creer")), "annonce vendue : ajout au panier refusé")
ok("remise en vente" in texte(post(club, "/market/1/vendu", page="/creer")), "annonce remise en vente")
ok("transmis" in texte(post(club2, "/signaler", dict(kind="listing", target_id="1", reason="Arnaque"), "/creer")), "signalement d’une annonce")
ok(club.post("/signaler", data={"csrf": csrf(club, "/creer"), "kind": "listing", "target_id": "1", "reason": "Arnaque"}).status_code == 400, "pas de signalement de sa propre annonce")
post(club, "/market/publier", dict(player_name="Temp T.", position="Gardien", age="30"), "/market")
ok("Annonce retirée" in texte(post(club, "/market/3/supprimer", page="/creer")) and DB().execute("select count(*) from listings where id=3").fetchone()[0] == 0, "annonce retirée")
DB().execute("delete from reports").connection.commit()

ok_sport = lambda: DB().execute("select count(*) from listings where sport is null").fetchone()[0] == 0
# ---------- filtres du Market ----------
DB().execute("update users set sport='basketball' where identifier='club2@test.com'").connection.commit()
post(club2, "/market/publier", dict(player_name="Panier P.", position="Meneur", age="19"), "/market")
mk = lambda q: texte(club.get("/market" + q))
t = mk("?sport=basketball"); ok("Panier P." in t and "Ismaël D." not in t and "Cheikh S." not in t, "filtre par sport")
t = mk("?poste=attaq"); ok("Ismaël D." in t and "Panier P." not in t, "filtre par poste (recherche partielle, majuscules ignorées)")
t = mk("?age_min=20&age_max=25"); ok("Ismaël D." in t and "Panier P." not in t and "Cheikh S." not in t, "filtre par âge (min et max)")
t = mk("?age_max=19"); ok("Panier P." in t and "Cheikh S." in t and "Ismaël D." not in t, "filtre âge maximum")
t = mk("?sport=football&age_min=20"); ok("Ismaël D." in t and "Cheikh S." not in t, "filtres combinés")
post(club, "/market/1/vendu", page="/creer"); t = mk("?dispo=1"); ok("Ismaël D." not in t and "Panier P." in t, "masquer les joueurs vendus")
post(club, "/market/1/vendu", page="/creer")
ok("Aucun joueur ne correspond" in mk("?poste=zzz") and "Aucun joueur ne correspond" in mk("?poste=%25"), "aucun résultat ; % traité comme du texte")
ok("Ismaël D." in mk("?sport=n-importe-quoi&age_min=abc&age_max=-5"), "valeurs invalides ignorées")
ok("filtres actifs" in mk("?sport=football") and "filtres actifs" not in mk(""), "indication des filtres actifs")
post(club, "/market/publier", dict(player_name="Yao A.", position="Défenseur", age="31"), "/market")
ok("Yao A." in mk("?poste=defenseur") and "Yao A." in mk("?poste=DÉFENSEUR") and "Ismaël D." not in mk("?poste=defenseur"), "poste : accents et majuscules ignorés")
ok("Yao A." in mk("?sport=football") and ok_sport(), "sport de l’annonce : celui du vendeur par défaut")

# ---------- recherche ----------
ok("Joueur Un" in texte(club.get("/recherche?q=joueur")), "un club trouve un joueur")
t = texte(joueur.get("/recherche?q=s")); ok("FC Test" in t and "Agent Un" not in t, "un joueur ne trouve que des clubs")
ok("Aucun résultat" in texte(club.get("/recherche?q=%25")), "caractère % traité comme du texte")

# ---------- profil ----------
r = post(joueur, "/profil/modifier", {"name": "Joueur Un", "position": "Meneur", "city": "Abidjan", "bio": "Meneur de jeu <i>rapide</i>", "photo": (png(), "me.png")}, "/profil/modifier")
t = texte(r); ok("Profil mis à jour" in t and "Abidjan" in t and "&lt;i&gt;rapide" in t and "/img/" in t, "profil modifié : ville, poste, description, photo")
ok("non valide" in texte(post(joueur, "/profil/modifier", {"name": "J", "photo": (io.BytesIO(b"nope"), "x.png")}, "/profil/modifier")), "photo de profil invalide refusée")
ok("Mot de passe actuel incorrect" in texte(post(joueur, "/profil/mot-de-passe", dict(actuel="faux", nouveau="nouveaumotdepasse"), "/profil/modifier")), "changement de mot de passe : ancien requis")
autre = client(); post(autre, "/connexion", dict(identifier="joueur@test.com", password="motdepasse123"), "/connexion")
ok("modifié" in texte(post(joueur, "/profil/mot-de-passe", dict(actuel="motdepasse123", nouveau="nouveaumotdepasse"), "/profil/modifier")), "mot de passe changé")
ok(joueur.get("/").status_code == 200 and autre.get("/").status_code == 302, "session courante gardée, autres appareils déconnectés")

# ---------- blocage et signalement ----------
ok("bloqué" in texte(post(club, "/bloquer/2", page="/creer")), "club bloque le joueur")
ok(joueur.get("/profil/1").status_code == 404 and club.get("/profil/2").status_code == 404, "profils inaccessibles entre bloqués")
ok(joueur.get("/messages/1").status_code == 403, "messages impossibles entre bloqués")
ok("Joueur Un" not in texte(club.get("/recherche?q=joueur")) and "Bonjour &lt;b&gt;" not in texte(joueur.get("/")), "recherche et fil : bloqués masqués")
ok("Joueur Un" in texte(club.get("/profil/modifier")) and "débloqué" in texte(post(club, "/bloquer/2", page="/creer")), "déblocage depuis la liste")
ok("transmis" in texte(post(joueur, "/signaler", dict(kind="post", target_id="1", reason="Arnaque"), "/creer")), "signalement d’une publication")
ok(joueur.post("/signaler", data={"csrf": csrf(joueur, "/creer"), "kind": "post", "target_id": "1", "reason": "n'importe quoi"}).status_code == 400, "motif invalide refusé")
ok(joueur.get("/admin").status_code == 403, "administration réservée aux administrateurs")
DB().execute("update users set is_admin=1 where id=3").connection.commit()
ok("Arnaque" in texte(agent.get("/admin")), "l’administrateur voit les signalements")
rid0 = DB().execute("select id from reports where kind='post' and status='ouvert'").fetchone()[0]
r = post(agent, f"/admin/signalement/{rid0}/suspendre", page="/creer"); ok("traité" in texte(r), "signalement traité")
ok("suspendu" in texte(post(client(), "/connexion", dict(identifier="club@test.com", password="motdepasse123"), "/connexion")), "compte suspendu : connexion refusée")
ok(club.get("/").status_code == 302, "compte suspendu : session fermée")
post(agent, "/admin/utilisateur/1/retablir", page="/creer")
ok("suspendu" not in texte(post(client(), "/connexion", dict(identifier="club@test.com", password="motdepasse123"), "/connexion")), "compte rétabli")
club = client(); post(club, "/connexion", dict(identifier="club@test.com", password="motdepasse123"), "/connexion")

# annonce signalée : l'administrateur la supprime
post(club2, "/signaler", dict(kind="listing", target_id="2", reason="Arnaque"), "/creer")
ok("Annonce Market" in texte(agent.get("/admin")), "l’administrateur voit l’annonce signalée")
rid = DB().execute("select id from reports where kind='listing' and status='ouvert'").fetchone()[0]
post(agent, f"/admin/signalement/{rid}/supprimer", page="/creer")
ok(DB().execute("select count(*) from listings where id=2").fetchone()[0] == 0, "l’administrateur supprime l’annonce signalée")

# message signalé : une copie reste visible pour l'administrateur même si l'auteur le supprime
post(club, "/messages/2", dict(body="Message à signaler"), "/messages/2")
mm = DB().execute("select id from messages where body='Message à signaler'").fetchone()[0]
ok(club.post("/signaler", data={"csrf": csrf(club, "/creer"), "kind": "message", "target_id": str(mm), "reason": "Arnaque"}).status_code == 404, "l’auteur ne peut pas signaler son propre message")
ok("transmis" in texte(post(joueur, "/signaler", dict(kind="message", target_id=str(mm), reason="Harcèlement ou menaces", retour="/messages/1"), "/creer")), "le destinataire signale un message")
post(club, f"/messages/{mm}/supprimer", page="/creer")
t = texte(agent.get("/admin")); ok("Message à signaler" in t and "supprimé depuis" in t, "l’administrateur voit la copie du message supprimé")
rm = DB().execute("select id from reports where kind='message' and status='ouvert'").fetchone()[0]
ok("traité" in texte(post(agent, f"/admin/signalement/{rm}/classer", page="/creer")), "signalement de message classé")

# ---------- supprimer sa publication, son compte ----------
ok("supprimée" in texte(post(club, "/publication/2/supprimer", page="/creer")) and not os.path.exists(fichier), "publication supprimée avec sa photo")
ok("incorrect" in texte(post(joueur, "/profil/supprimer", dict(actuel="faux"), "/profil/modifier")), "suppression de compte : mot de passe requis")
r = post(joueur, "/profil/supprimer", dict(actuel="nouveaumotdepasse"), "/profil/modifier"); ok("supprimés" in texte(r), "compte supprimé")
ok(DB().execute("select count(*) from users where identifier='joueur@test.com'").fetchone()[0] == 0 and DB().execute("select count(*) from messages where audio is not null").fetchone()[0] == 0, "données du compte supprimées (messages, vocaux)")

# ---------- mot de passe oublié ----------
n = len(MAILS); post(client(), "/mot-de-passe-oublie", dict(identifier="inconnu@test.com"), "/mot-de-passe-oublie"); ok(len(MAILS) == n, "aucun e-mail pour un compte inconnu")
ok("Si un compte correspond" in texte(post(client(), "/mot-de-passe-oublie", dict(identifier="club2@test.com"), "/mot-de-passe-oublie")), "même réponse pour un compte connu")
lien = re.search(r"(/reinitialisation/[\w\-.]+)", MAILS[-1][2]).group(1)
ok("8 caractères" in texte(post(client(), lien, dict(password="court"), lien)), "nouveau mot de passe trop court refusé")
ok("Mot de passe modifié" in texte(post(client(), lien, dict(password="encoreunautre1"), lien)), "mot de passe réinitialisé")
ok(client().get(lien).status_code == 302 and club2.get("/").status_code == 302, "lien à usage unique, anciennes sessions fermées")
ok(client().get("/reinitialisation/falsifie").status_code == 302, "lien falsifié refusé")
auth.DUREE_LIEN = 0; post(client(), "/mot-de-passe-oublie", dict(identifier="club2@test.com"), "/mot-de-passe-oublie"); time.sleep(1.1)
ok(client().get(re.search(r"(/reinitialisation/[\w\-.]+)", MAILS[-1][2]).group(1)).status_code == 302, "lien expiré refusé"); auth.DUREE_LIEN = 3600
auth._demandes.clear(); os.environ["IP_HEADER"] = "X-Forwarded-For"
def demande(ip=None):
    cl = client(); h = {"X-Forwarded-For": ip} if ip else {}
    return texte(cl.post("/mot-de-passe-oublie", data={"identifier": "x@test.com", "csrf": csrf(cl, "/mot-de-passe-oublie")}, headers=h, follow_redirects=True))
for _ in range(6): t = demande("9.9.9.9")
ok("Trop de demandes" in t and "Trop de demandes" not in demande("8.8.8.8"), "limite de demandes par IP")

# ---------- anciennes bases : migration automatique ----------
tmp = os.path.join(tempfile.mkdtemp(), "ancienne.sqlite"); con = sqlite3.connect(tmp)
con.execute("create table users (id integer primary key, role text, name text, sport text, identifier text, password_hash text, premium_until text, created_at text)")
con.execute("create table posts (id integer primary key, user_id integer, body text, created_at text)")
con.execute("create table messages (id integer primary key, sender_id integer, recipient_id integer, body text, audio text, created_at text)")
con.execute("insert into messages(sender_id, recipient_id, body) values (1, 2, 'ancien')")
con.execute("create table listings (id integer primary key, seller_id integer, player_name text, position text, age integer, price integer, created_at text)")
con.execute("insert into users(id, sport) values (7, 'handball')"); con.execute("insert into listings(seller_id, player_name, position, age) values (7, 'Vieux', 'Ailier', 20)")
con.commit(); con.close()
avant = app.config["DATABASE"]; app.config["DATABASE"] = tmp
with app.app_context(): db.init_db()
app.config["DATABASE"] = avant
cols = {r[1] for r in sqlite3.connect(tmp).execute("pragma table_info(users)")} | {r[1] for r in sqlite3.connect(tmp).execute("pragma table_info(posts)")}
ok({"email_verified", "bio", "photo", "suspended", "image"} <= cols, "migration d’une ancienne base")
ok(sqlite3.connect(tmp).execute("select sport from listings").fetchone()[0] == "handball", "migration : anciennes annonces reçoivent le sport du vendeur")
ok(sqlite3.connect(tmp).execute("select read from messages").fetchone()[0] == 1, "migration : anciens messages marqués comme lus")

# ---------- icône et installation sur l'écran d'accueil ----------
cl = client(); r = cl.get("/manifest.webmanifest")
m = json.loads(r.get_data(as_text=True)); ok(r.mimetype == "application/manifest+json" and m["display"] == "standalone" and len(m["icons"]) == 2, "manifeste de l’application")
ok(cl.get("/favicon.ico").status_code == 200 and cl.get("/static/icon-512.png").status_code == 200 and cl.get("/static/apple-touch-icon.png").status_code == 200, "favicon et icônes")
ok('rel="manifest"' in texte(cl.get("/connexion")) and 'rel="apple-touch-icon"' in texte(cl.get("/connexion")), "pages reliées au manifeste et aux icônes")
tmp2 = os.path.join(tempfile.mkdtemp(), "ancienne2.sqlite"); con = sqlite3.connect(tmp2)
con.execute("create table users (id integer primary key, role text, name text, sport text, identifier text, password_hash text, premium_until text, created_at text)")
con.execute("create table reports (id integer primary key autoincrement, reporter_id integer not null, kind text not null check (kind in ('post','comment','user')), target_id integer not null, reason text not null, status text not null default 'ouvert', created_at text not null default current_timestamp)")
con.execute("insert into reports(reporter_id, kind, target_id, reason) values (1,'post',5,'Arnaque')"); con.commit(); con.close()
app.config["DATABASE"] = tmp2
with app.app_context(): db.init_db()
con = sqlite3.connect(tmp2); con.execute("insert into reports(reporter_id, kind, target_id, reason) values (1,'listing',2,'Arnaque')")
ok(con.execute("select count(*) from reports").fetchone()[0] == 2, "migration : anciens signalements gardés, annonces signalables")
app.config["DATABASE"] = avant
print("\nTOUS LES TESTS PASSENT")
