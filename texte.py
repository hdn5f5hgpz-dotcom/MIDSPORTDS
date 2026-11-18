"""Outils de texte pour les recherches."""
import unicodedata


def normaliser(texte):
    """Minuscules et sans accents (« Défenseur » = « defenseur »)."""
    if texte is None:
        return ""
    decompose = unicodedata.normalize("NFKD", str(texte).lower())
    return "".join(c for c in decompose if not unicodedata.combining(c))


def motif_like(texte):
    """Motif LIKE « contient ce texte » (sans accents) ; % _ et \\ sont traités comme du texte."""
    t = normaliser(texte).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + t + "%"
