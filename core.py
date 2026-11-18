"""Outils partagés : images, blocages."""
import os
import re
import uuid
from flask import current_app
from PIL import Image, ImageOps, UnidentifiedImageError
from db import get_db

Image.MAX_IMAGE_PIXELS = 25_000_000
NOM_IMAGE = re.compile(r"^[0-9a-f]{32}\.jpg$")
NOM_AUDIO = re.compile(r"^[0-9a-f]{32}\.\w{2,4}$")
# ids des comptes bloqués par moi ou qui m'ont bloqué (paramètre nommé :me)
SQL_BLOQUES = ("(SELECT blocked_id FROM blocks WHERE blocker_id = :me "
               "UNION SELECT blocker_id FROM blocks WHERE blocked_id = :me)")


def dossier_images():
    d = os.path.join(current_app.config["UPLOAD_DIR"], "images")
    os.makedirs(d, exist_ok=True)
    return d


def enregistrer_image(fichier, max_px=1280):
    """Vérifie une image (JPEG, PNG, WebP), retire ses métadonnées (dont la position GPS),
    la réduit et l'enregistre en JPEG. Retourne le nom du fichier, ou None si invalide."""
    if not fichier or not fichier.filename:
        return None
    try:
        img = Image.open(fichier.stream)
        if img.format not in ("JPEG", "PNG", "WEBP"):
            return None
        img = ImageOps.exif_transpose(img).convert("RGBA")
        fond = Image.new("RGB", img.size, "white")
        fond.paste(img, mask=img.split()[3])
        fond.thumbnail((max_px, max_px))
        nom = uuid.uuid4().hex + ".jpg"
        fond.save(os.path.join(dossier_images(), nom), "JPEG", quality=85)
        return nom
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
        return None


def supprimer_image(nom):
    if nom and NOM_IMAGE.match(nom):
        try:
            os.remove(os.path.join(dossier_images(), nom))
        except OSError:
            pass


def supprimer_audio(nom):
    if nom and NOM_AUDIO.match(nom):
        try:
            os.remove(os.path.join(current_app.config["UPLOAD_DIR"], nom))
        except OSError:
            pass


def bloque(a, b):
    """Vrai si l'un des deux comptes a bloqué l'autre."""
    return bool(get_db().execute(
        "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",
        (a, b, b, a)).fetchone())
