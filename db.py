import sqlite3
import click
from flask import current_app, g
from texte import normaliser
from werkzeug.security import generate_password_hash

# colonnes ajoutées après la première version : ajoutées automatiquement aux anciennes bases
COLONNES = {
    "users": {"bio": "TEXT", "city": "TEXT", "position": "TEXT", "photo": "TEXT", "terms_at": "TEXT",
              "email_verified": "INTEGER NOT NULL DEFAULT 0", "is_admin": "INTEGER NOT NULL DEFAULT 0",
              "suspended": "INTEGER NOT NULL DEFAULT 0"},
    "posts": {"image": "TEXT"},
    "listings": {"sold": "INTEGER NOT NULL DEFAULT 0", "sport": "TEXT"},
    "messages": {"read": "INTEGER NOT NULL DEFAULT 0"},
    "reports": {"detail": "TEXT", "author_id": "INTEGER"},
}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.create_function("norm", 1, normaliser, deterministic=True)   # minuscules et sans accents
    return g.db


def close_db(_=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = get_db()
    with current_app.open_resource("schema.sql") as f:
        conn.executescript(f.read().decode())
    ajoutees = set()
    for table, cols in COLONNES.items():
        existantes = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for nom, typ in cols.items():
            if nom not in existantes:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {nom} {typ}")
                ajoutees.add((table, nom))
    if ("listings", "sport") in ajoutees:         # anciennes annonces : sport du vendeur
        conn.execute("UPDATE listings SET sport = (SELECT sport FROM users WHERE users.id = listings.seller_id)")
    if ("messages", "read") in ajoutees:          # anciens messages : considérés comme déjà lus
        conn.execute("UPDATE messages SET read = 1")
    # anciennes bases : la table des signalements limitait les types ; on la reconstruit sans cette limite
    ancien = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'reports'").fetchone()
    if ancien and "check" in ancien[0].lower():
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.executescript("ALTER TABLE reports RENAME TO reports_old;")
        with current_app.open_resource("schema.sql") as f:
            conn.executescript(f.read().decode())
        conn.executescript("INSERT INTO reports(id, reporter_id, kind, target_id, reason, status, created_at) "
                           "SELECT id, reporter_id, kind, target_id, reason, status, created_at FROM reports_old; "
                           "DROP TABLE reports_old;")
        conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()


def init_app(app):
    app.teardown_appcontext(close_db)

    @app.cli.command("make-admin")
    @click.argument("email")
    def make_admin(email):
        """Donne les droits d'administrateur au compte portant cet e-mail."""
        conn = get_db()
        cur = conn.execute("UPDATE users SET is_admin = 1 WHERE identifier = ?", (email.strip().lower(),))
        conn.commit()
        click.echo("Administrateur défini." if cur.rowcount else "Aucun compte avec cet e-mail.")

    @app.cli.command("seed")
    def seed():
        """Données de démonstration (développement uniquement)."""
        conn = get_db()
        pw = generate_password_hash("motdepasse123")
        demo = [("club", "FC Abidjan", "football", "fcabidjan@example.com"),
                ("club", "Basket Dakar", "basketball", "basketdakar@example.com"),
                ("agent", "Moussa K.", "football", "moussa@example.com"),
                ("joueur", "Karim M.", "basketball", "karim@example.com")]
        for role, name, sport, ident in demo:
            conn.execute("INSERT OR IGNORE INTO users(role,name,sport,identifier,password_hash,email_verified)"
                         " VALUES (?,?,?,?,?,1)", (role, name, sport, ident, pw))
        conn.execute("INSERT INTO posts(user_id, body) VALUES (1, 'Le derby de samedi : qui mérite le titre de joueur du mois ?')")
        conn.execute("INSERT INTO listings(seller_id, player_name, position, age, price, sport) VALUES (1,'Ismaël D.','Attaquant',22,5000000,'football')")
        conn.execute("INSERT INTO listings(seller_id, player_name, position, age, sport) VALUES (2,'Cheikh S.','Meneur',19,'basketball')")
        conn.commit()
        click.echo("Comptes de démo (mot de passe : motdepasse123) : "
                   "fcabidjan@example.com, basketdakar@example.com, moussa@example.com, karim@example.com")
