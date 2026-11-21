import json
import os
import secrets
from datetime import timedelta
from flask import Flask, abort, render_template, request, send_from_directory, session, url_for
from markupsafe import Markup
import auth
import db
import social
import views


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    prod = bool(os.environ.get("MIDSPORT_PROD"))
    if prod and not os.environ.get("SECRET_KEY"):
        raise RuntimeError("Définissez SECRET_KEY en production.")
    if prod and not (os.environ.get("BREVO_API_KEY") or os.environ.get("SMTP_HOST")):
        raise RuntimeError("Définissez BREVO_API_KEY et MAIL_FROM (ou SMTP_HOST, SMTP_USER, SMTP_PASSWORD) : "
                           "sans e-mail, personne ne peut valider son compte.")
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-seulement-changez-moi"),
        DATABASE=os.path.join(app.instance_path, "midsport.sqlite"),
        UPLOAD_DIR=os.path.join(app.instance_path, "uploads"),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=prod,
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    )
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    db.init_app(app)
    with app.app_context():
        db.init_db()
    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(social.bp)

    @app.before_request
    def protection_csrf():
        session.setdefault("csrf", secrets.token_hex(16))
        if request.method == "POST":
            envoye = request.form.get("csrf", "")
            if not secrets.compare_digest(session["csrf"], envoye):
                abort(400)

    @app.after_request
    def en_tetes(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    app.jinja_env.globals["csrf_field"] = lambda: Markup(
        '<input type="hidden" name="csrf" value="%s">' % session["csrf"])

    @app.get("/favicon.ico")
    def favicon():
        return send_from_directory(app.static_folder, "favicon.ico")

    @app.get("/manifest.webmanifest")
    def manifest():
        icones = [{"src": url_for("static", filename=f"icon-{t}.png"), "sizes": f"{t}x{t}",
                   "type": "image/png", "purpose": "any maskable"} for t in (192, 512)]
        corps = {"name": "MidSport", "short_name": "MidSport", "lang": "fr", "start_url": "/", "scope": "/",
                 "display": "standalone", "background_color": "#f0f2f5", "theme_color": "#0866ff", "icons": icones}
        return app.response_class(json.dumps(corps), mimetype="application/manifest+json")

    app.jinja_env.globals["RAISONS"] = social.RAISONS

    MESSAGES = {400: "Requête invalide. Rechargez la page et réessayez.",
                403: "Vous n’avez pas accès à cette page.",
                404: "Cette page n’existe pas ou n’est plus disponible.",
                413: "Fichier trop volumineux (10 Mo maximum).",
                500: "Une erreur est survenue. Réessayez dans un moment."}

    def erreur(e):
        code = getattr(e, "code", 500)
        return render_template("erreur.html", code=code, message=MESSAGES.get(code, MESSAGES[500])), code
    for c in MESSAGES:
        app.register_error_handler(c, erreur)
    app.jinja_env.filters["fr"] = lambda n: f"{n:,}".replace(",", " ")
    return app


app = create_app()

